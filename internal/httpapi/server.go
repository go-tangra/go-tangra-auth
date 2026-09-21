package httpapi

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/go-freya/freya/services/auth/api/openapi"
	"github.com/go-freya/freya/services/auth/internal/tenant"
	"github.com/go-freya/freya/services/auth/internal/tenantctx"
	"github.com/go-freya/freya/transport"
	"github.com/go-freya/freya/transport/edge"
)

// ConsolePrefix is where the SPA is served (Vite base "/console/").
const ConsolePrefix = "/console"

// Route is a declared method/path pair.
type Route struct{ Method, Path string }

func (r Route) String() string { return r.Method + " " + r.Path }

// Option configures the handler.
type Option func(*Server)

// WithSessions installs the session resolver.
func WithSessions(r SessionResolver) Option { return func(s *Server) { s.sessions = r } }

// WithConsole serves the built console from dist for non-API paths.
func WithConsole(dist fs.FS) Option { return func(s *Server) { s.console = dist } }

// WithGatewayMode tells the console that a platform shell owns "/" (sign-in
// returns there instead of the console home).
func WithGatewayMode() Option { return func(s *Server) { s.gatewayMode = true } }

// WithRemote serves the federated remote build (mf-manifest.json, assets)
// under RemotePrefix; the gateway relays /m/auth/* here in gateway mode.
func WithRemote(dist fs.FS) Option { return func(s *Server) { s.remote = dist } }

// RemotePrefix is where the federated remote is served to the gateway.
const RemotePrefix = "/ui"

// Server is the browser-facing API: every declared OpenAPI route is mounted
// (501 until a story implements it), requests are validated against the
// document, the session cookie yields the actor, and the console SPA is served
// for everything else.
type Server struct {
	rt          transport.Runtime
	edge        *edge.Server
	doc         *openapi3.T
	router      routers.Router
	mux         *http.ServeMux
	mu          sync.RWMutex
	handlers    map[Route]http.Handler
	declared    []Route
	sessions    SessionResolver
	console     fs.FS
	remote      fs.FS
	gatewayMode bool
	handler     http.Handler
	grants      *tenant.Grants
}

// LoadDocument parses and validates the embedded OpenAPI document.
func LoadDocument() (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(openapi.Console)
	if err != nil {
		return nil, fmt.Errorf("httpapi: openapi: %w", err)
	}
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		return nil, fmt.Errorf("httpapi: openapi: %w", err)
	}
	return doc, nil
}

// DeclaredRoutes lists every operation in the document, sorted.
func DeclaredRoutes(doc *openapi3.T) []Route {
	var out []Route
	for p, item := range doc.Paths.Map() {
		for m := range item.Operations() {
			out = append(out, Route{Method: strings.ToUpper(m), Path: p})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// NewHandler builds the API without binding a listener (tests, embedding).
func NewHandler(rt transport.Runtime, opts ...Option) (*Server, error) {
	doc, err := LoadDocument()
	if err != nil {
		return nil, err
	}
	// The router must not pin requests to the document's servers host.
	servers := doc.Servers
	doc.Servers = nil
	router, err := gorillamux.NewRouter(doc)
	doc.Servers = servers
	if err != nil {
		return nil, fmt.Errorf("httpapi: router: %w", err)
	}
	s := &Server{rt: rt, doc: doc, router: router, mux: http.NewServeMux(), handlers: map[Route]http.Handler{}}
	for _, o := range opts {
		o(s)
	}
	s.declared = DeclaredRoutes(doc)
	for _, rt := range s.declared {
		rt := rt
		s.mux.Handle(rt.Method+" "+rt.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			h := s.handlers[rt]
			s.mu.RUnlock()
			if h == nil {
				WriteError(w, ErrNotImplemented.Status, ErrNotImplemented.Reason)
				return
			}
			h.ServeHTTP(w, r)
		}))
	}
	if s.console != nil {
		s.mux.Handle(ConsolePrefix+"/", http.StripPrefix(ConsolePrefix, consoleHandler(s.console, s.gatewayMode)))
		s.mux.Handle("GET /{$}", http.RedirectHandler(ConsolePrefix+"/", http.StatusFound))
	}
	if s.remote != nil {
		s.mux.Handle("GET "+RemotePrefix+"/", http.StripPrefix(RemotePrefix, remoteHandler(s.remote)))
	}
	s.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteError(w, http.StatusNotFound, ErrNotFound.Reason)
	}))
	s.handler = s.validate(s.session(s.withGrant(s.mux)))
	return s, nil
}

// New builds the API and binds it to an edge listener.
func New(rt transport.Runtime, cfg edge.Config, opts ...Option) (*Server, error) {
	s, err := NewHandler(rt, opts...)
	if err != nil {
		return nil, err
	}
	e, err := edge.NewServer(rt, cfg)
	if err != nil {
		return nil, err
	}
	e.HandlePrefix("/", s.handler)
	s.edge = e
	return s, nil
}

// withGrant rewrites the request for operators acting under a grant so
// admin handlers see an owner-equivalent actor of the target tenant.
func (s *Server) withGrant(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(OperatorTenantHeader) != "" && strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
			a, ctx, err := s.adminScope(r)
			if err != nil {
				Fail(w, r, nil, err)
				return
			}
			r = r.WithContext(tenantctx.WithActor(ctx, a))
		}
		h.ServeHTTP(w, r)
	})
}

// Handle installs h for a declared route; undeclared routes are refused so
// the contract and the implementation cannot drift.
func (s *Server) Handle(method, path string, h http.Handler) error {
	rt := Route{Method: strings.ToUpper(method), Path: path}
	if !s.isDeclared(rt) {
		return fmt.Errorf("httpapi: route %s is not declared in the OpenAPI document", rt)
	}
	s.mu.Lock()
	s.handlers[rt] = h
	s.mu.Unlock()
	return nil
}

// HandleFunc is Handle for a function.
func (s *Server) HandleFunc(method, path string, h func(http.ResponseWriter, *http.Request)) error {
	return s.Handle(method, path, http.HandlerFunc(h))
}

// MustHandle panics on an undeclared route (wiring errors are programming errors).
func (s *Server) MustHandle(method, path string, h func(http.ResponseWriter, *http.Request)) {
	if err := s.HandleFunc(method, path, h); err != nil {
		panic(err)
	}
}

func (s *Server) isDeclared(rt Route) bool {
	for _, d := range s.declared {
		if d == rt {
			return true
		}
	}
	return false
}

// Declared lists routes from the document; Implemented lists those with a handler.
func (s *Server) Declared() []Route { return append([]Route(nil), s.declared...) }
func (s *Server) Implemented() []Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Route
	for rt := range s.handlers {
		out = append(out, rt)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// Document returns the parsed OpenAPI document.
func (s *Server) Document() *openapi3.T { return s.doc }

// Handler returns the full chain (validation → session → routes).
func (s *Server) Handler() http.Handler { return s.handler }

// Edge returns the bound listener (nil for NewHandler).
func (s *Server) Edge() *edge.Server { return s.edge }

// Start/Stop delegate to the edge listener.
func (s *Server) Start(ctx context.Context) error { return s.edge.Start(ctx) }
func (s *Server) Stop(ctx context.Context) error  { return s.edge.Stop(ctx) }
