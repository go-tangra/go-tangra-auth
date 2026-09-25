// Package app wires the auth service: configuration → Freya runtime → store,
// cache, OpenFGA, email, audit → browser API on the edge listener and the
// auth.v1 gRPC API. cmd/authsvc and the integration harness both use it.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/audit/auditdb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz"
	"github.com/go-tangra/go-tangra-auth/v4/internal/authz/authzdb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/cache"
	"github.com/go-tangra/go-tangra-auth/v4/internal/config"
	"github.com/go-tangra/go-tangra-auth/v4/internal/crypto"
	"github.com/go-tangra/go-tangra-auth/v4/internal/directory"
	"github.com/go-tangra/go-tangra-auth/v4/internal/directory/directorydb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email"
	"github.com/go-tangra/go-tangra-auth/v4/internal/email/emaildb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-auth/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-auth/v4/internal/invite"
	"github.com/go-tangra/go-tangra-auth/v4/internal/invite/invitedb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/ldapdir"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa"
	"github.com/go-tangra/go-tangra-auth/v4/internal/mfa/mfadb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/oauth"
	"github.com/go-tangra/go-tangra-auth/v4/internal/oauth/oauthdb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password"
	"github.com/go-tangra/go-tangra-auth/v4/internal/password/passworddb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session"
	"github.com/go-tangra/go-tangra-auth/v4/internal/session/sessiondb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenant/tenantdb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token"
	"github.com/go-tangra/go-tangra-auth/v4/internal/token/tokendb"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user"
	"github.com/go-tangra/go-tangra-auth/v4/internal/user/userdb"
	"github.com/go-tangra/go-tangra/v4"
	"github.com/go-tangra/go-tangra/v4/transport/edge"
)

// Options override infrastructure (tests) and attach story handlers.
type Options struct {
	Logger    slog.Handler
	KV        cache.KV        // nil = Valkey from config
	FGA       authz.Backend   // nil = OpenFGA from config
	Deliverer email.Deliverer // nil = from config (notification, or the log sink)
	Console   fs.FS           // nil = no console
	Remote    fs.FS           // nil = no federated remote (gateway mode)
	Sessions  httpapi.SessionResolver
	GRPC      grpcapi.Handlers
	Freya     []freya.Option
	Migrate   bool
}

// App holds every wired component.
type App struct {
	Cfg       config.Config
	Log       *slog.Logger
	Freya     *freya.App
	Store     *store.Store
	Cache     *cache.Cache
	FGA       authz.Backend
	Authz     *authz.Client
	Envelope  *crypto.Envelope
	Deliverer email.Deliverer
	Outbox    *email.Outbox
	Audit     *audit.Writer
	HTTP      *httpapi.Server
	Sessions  *session.Manager
	Signin    *user.Service
	Ring      *token.Ring
	Tokens    *token.Issuer
	OAuth     *oauth.Service
	Invites   *invite.Service
	Admin     *user.Admin
	Assigner  *authz.Assigner
	Groups    *authz.Groups
	Profiles  *user.Profiles
	Avatars   *user.Avatars
	Registry  *authz.Registry
	Roles     *authz.Roles
	Decider   *authz.Decider
	MFA       *mfa.Service
	Changer   *password.Changer
	Recovery  *password.Recovery
	Tenants   *tenant.Service
	Grants    *tenant.Grants
	// Directories is nil when directory.enabled is false (feature 016).
	Directories *directory.Service
	closers     []func()
}

// PlatformTenantSlug is the tenant operators belong to.
const PlatformTenantSlug = "platform"

// PlatformTenantID is a FIXED, well-known UUID for the platform tenant so it
// coincides with lcm's mesh-CA tenant (services/lcm/internal/app.MeshTenantID):
// the operator then browses the same tenant the platform SVIDs are issued under
// and can see/manage them. Customer tenants get random IDs as usual.
const PlatformTenantID = "00000000-0000-0000-0000-000000000001"

// Build validates cfg and connects every dependency; nothing is served yet.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	log := slog.New(handler)
	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}
	built := &App{Cfg: cfg, Log: log}
	a = built
	defer func() {
		// On failure the named return is already nil; release what built acquired.
		if err != nil {
			built.Close()
		}
	}()
	kek, err := cfg.KEK.Load()
	if err != nil {
		return nil, err
	}
	if a.Envelope, err = crypto.NewEnvelope(kek); err != nil {
		return nil, err
	}
	if o.Migrate {
		dsn := cfg.DB.MigrateDSN
		if dsn == "" {
			dsn = cfg.DB.DSN
		}
		if err := store.Migrate(ctx, dsn); err != nil {
			return nil, err
		}
	}
	if a.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Store.Close)
	kv := o.KV
	if kv == nil {
		vc := cache.ValkeyConfig{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			if vc.CAPEM, err = os.ReadFile(cfg.Valkey.CAFile); err != nil {
				return nil, fmt.Errorf("valkey ca: %w", err)
			}
		}
		if kv, err = cache.NewValkey(vc); err != nil {
			return nil, err
		}
	}
	a.Cache = cache.New(kv)
	a.closers = append(a.closers, a.Cache.Close)
	a.FGA = o.FGA
	if a.FGA == nil {
		if a.FGA, err = authz.NewSDKBackend(authz.SDKConfig{URL: cfg.OpenFGA.URL, PresharedKey: cfg.OpenFGA.PresharedKey, StoreID: cfg.OpenFGA.StoreID, AllowPlaintext: cfg.OpenFGA.AllowPlaintext}); err != nil {
			return nil, err
		}
	}
	if _, _, err = authz.Bootstrap(ctx, a.FGA, "auth"); err != nil {
		return nil, err
	}
	a.Audit = audit.NewWriter(a.Store, func(err error) { log.Error("audit write failed", "err", err) })
	a.closers = append(a.closers, a.Audit.Close)
	a.Authz = authz.New(a.FGA, a.Cache, a.onRefusal)
	a.Deliverer = o.Deliverer
	if a.Deliverer == nil {
		switch cfg.Email.Mode() {
		case "log":
			a.Deliverer = email.LogSink{Log: log}
		default:
			a.Deliverer = email.NewNotifier(a.notificationConn)
		}
	}
	a.Outbox = email.NewOutbox(a.Envelope, a.Deliverer, emaildb.StoreQueue{Store: a.Store}, 8, func(err error) { log.Warn("email delivery", "err", err) }).
		OnGiveUp(a.onEmailGivenUp)
	fopts := append([]freya.Option{freya.WithLogger(handler)}, o.Freya...)
	if a.Freya, err = freya.New(cfg.Config, fopts...); err != nil {
		return nil, err
	}
	a.closers = append(a.closers, a.Freya.Close)
	a.Sessions = session.New(sessiondb.DBStore{St: a.Store}, a.Cache, a.Audit)
	a.Signin = user.New(userdb.DBStore{St: a.Store}, a.Cache, a.Audit, a.Sessions, nil)
	a.Ring = token.NewRing(tokendb.StoreKeys{St: a.Store}, a.Envelope, token.Config{AccessLifetime: cfg.Token.AccessLifetime, RotationInterval: cfg.Token.RotationInterval, RetiringPeriod: cfg.Token.RetiringPeriod, ClockSkew: cfg.Token.ClockSkew})
	if err = a.Ring.Load(ctx); err != nil {
		return nil, err
	}
	a.Tokens = token.NewIssuer(a.Ring, cfg.Issuer)
	a.OAuth = oauth.New(oauthdb.DBClients{St: a.Store}, a.Cache, a.Tokens, a.Audit)
	var resolver httpapi.SessionResolver = a.Sessions
	if o.Sessions != nil {
		resolver = o.Sessions
	}
	hopts := []httpapi.Option{httpapi.WithSessions(resolver)}
	if o.Console != nil {
		hopts = append(hopts, httpapi.WithConsole(o.Console))
	}
	if o.Remote != nil {
		hopts = append(hopts, httpapi.WithRemote(o.Remote))
	}
	if cfg.Gateway.Enabled {
		// Gateway mode: the browser API rides on the Freya HTTP server; only the
		// gateway (mTLS peer, policed by policy.yaml) can reach it.
		if a.HTTP, err = httpapi.NewHandler(a.Freya, append(hopts, httpapi.WithGatewayMode())...); err != nil {
			return nil, err
		}
		a.Freya.HTTP().HandlePrefix("/", a.HTTP.Handler())
	} else {
		ec := edge.Config{Addr: cfg.Edge.Addr, Env: cfg.Env, CertFile: cfg.Edge.CertFile, KeyFile: cfg.Edge.KeyFile,
			AllowedOrigins: cfg.Edge.AllowedOrigins, TrustedProxies: cfg.Edge.TrustedProxies, RateLimit: cfg.Edge.RateLimit}
		if a.HTTP, err = httpapi.New(a.Freya, ec, hopts...); err != nil {
			return nil, err
		}
		a.Freya.AddServer(a.HTTP)
	}
	a.HTTP.RegisterUS1(httpapi.US1Deps{Signin: a.Signin, Sessions: a.Sessions, Tokens: a.Tokens, Ring: a.Ring, Tenants: userdb.DBStore{St: a.Store}, Profiles: profiles{st: a.Store}})
	a.HTTP.RegisterOAuth(httpapi.OAuthDeps{OAuth: a.OAuth})
	a.Invites = invite.New(invitedb.DBStore{St: a.Store}, a.Outbox, a.Authz, a.Audit, cfg.Issuer)
	a.Admin = user.NewAdmin(userdb.DBAdminStore{St: a.Store}, a.Sessions, a.Audit)
	a.Assigner = authz.NewAssigner(authzdb.DBRoleStore{St: a.Store}, a.Authz, a.Audit)
	a.HTTP.RegisterUS2(httpapi.US2Deps{Invites: a.Invites, Admin: a.Admin, Assigner: a.Assigner, Audit: auditdb.DBQuerier{St: a.Store}, Sessions: a.Sessions})
	roleStore := authzdb.DBRoleStore{St: a.Store}
	a.Groups = authz.NewGroups(authzdb.DBGroupStore{DBRoleStore: roleStore}, a.Authz, a.Audit)
	a.HTTP.RegisterGroups(httpapi.GroupDeps{Groups: a.Groups})
	a.Invites.WithEscalation(authz.InviteEscalation{Assigner: a.Assigner, Groups: a.Groups})
	a.Registry = authz.NewRegistry(authzdb.DBPermissionStore{St: a.Store}, a.Authz, a.Audit)
	a.Roles = authz.NewRoles(authzdb.DBRoleCRUDStore{DBRoleStore: roleStore}, a.Authz, authz.NewEscalation(a.Authz), a.Audit)
	a.Decider = authz.NewDecider(authzdb.DBStatusStore{DBRoleStore: roleStore}, a.Authz, a.Audit)
	a.HTTP.RegisterUS3(httpapi.US3Deps{Roles: a.Roles, Registry: a.Registry})
	a.MFA = mfa.New(mfadb.DBStore{St: a.Store}, a.Cache, a.Envelope, a.Audit, cfg.MFA.Issuer)
	a.Signin.SetMFA(a.MFA)
	a.Changer = password.NewChanger(passworddb.DBChangeStore{St: a.Store}, a.Sessions, a.Audit)
	a.Recovery = password.NewRecovery(passworddb.DBRecoveryStore{St: a.Store}, a.Outbox, a.Sessions, a.Audit, cfg.Issuer)
	a.HTTP.RegisterUS4(httpapi.US4Deps{MFA: a.MFA, Changer: a.Changer, Recovery: a.Recovery})
	a.Profiles = user.NewProfiles(userdb.DBAdminStore{St: a.Store}, a.Audit)
	a.Avatars = user.NewAvatars(userdb.DBAdminStore{St: a.Store}, a.Audit, user.AvatarLimits{MaxBytes: cfg.Profile.AvatarMaxBytes, MaxPixels: cfg.Profile.AvatarMaxPixels, Size: cfg.Profile.AvatarSize, Concurrency: cfg.Profile.AvatarDecodeConcurrency})
	a.HTTP.RegisterProfiles(httpapi.ProfileDeps{Profiles: a.Profiles, Avatars: a.Avatars, Sessions: a.Sessions, Cache: a.Cache, LookupRatePerMinute: cfg.Profile.LookupRatePerMinute, MaxAvatarBytes: cfg.Profile.AvatarMaxBytes})
	tstore := tenantdb.DBStore{St: a.Store}
	a.Tenants = tenant.New(tstore, a.Invites, a.Sessions, a.Authz, a.Cache, a.Audit)
	a.Tenants.OnCreated = func(ctx context.Context, tid string) {
		if err := a.seedConsolePermissions(ctx, tid); err != nil {
			log.Error("console permissions", "tenant", tid, "err", err)
		}
	}
	a.Grants = tenant.NewGrants(tenantdb.DBGrantStore{DBStore: tstore}, a.Audit)
	a.HTTP.RegisterUS5(httpapi.US5Deps{Tenants: a.Tenants, Grants: a.Grants, Clients: clientStore{st: a.Store}, Audit: a.Audit})
	if err = a.buildDirectory(); err != nil {
		return nil, err
	}
	// Always mounted (the contract declares the routes); disabled answers 404.
	dd := httpapi.DirectoryDeps{Enabled: cfg.Directory.Enabled, Authz: a.Authz}
	if a.Directories != nil {
		dd.Directories = a.Directories
	}
	a.HTTP.RegisterDirectory(dd)
	h := o.GRPC
	if h.Keys == nil {
		h.Keys = &grpcapi.KeysServer{Ring: a.Ring, NotAfterGrace: func() (int64, int64) {
			return int64(cfg.Token.AccessLifetime / time.Second), int64(cfg.Token.ClockSkew / time.Second)
		}}
	}
	if h.Sessions == nil {
		h.Sessions = &grpcapi.SessionsServer{Sessions: a.Sessions, Tokens: a.Tokens, Audit: a.Audit, Poll: cfg.Session.RevocationPoll}
	}
	if h.Authorization == nil {
		h.Authorization = &grpcapi.AuthorizationServer{Decider: a.Decider, Registry: a.Registry, Tenants: a.activeTenantIDs, Roles: a.Roles}
	}
	if h.Enrollment == nil {
		h.Enrollment = &grpcapi.EnrollmentServer{Tokens: a.Tokens, Store: a.Store, Audit: a.Audit}
	}
	if h.Profiles == nil {
		h.Profiles = &grpcapi.ProfilesServer{Profiles: a.Profiles}
	}
	grpcapi.Register(a.Freya.GRPC(), h)
	// Every route the contract declares must have a handler: a declared but
	// unmounted route would answer 404 and hide a wiring mistake.
	if declared, mounted := len(httpapi.DeclaredRoutes(a.HTTP.Document())), len(a.HTTP.Implemented()); declared != mounted {
		return nil, fmt.Errorf("app: %d routes declared in the OpenAPI document, %d mounted", declared, mounted)
	}
	return a, nil
}

// clientStore adapts client applications (tenant scoped).
type clientStore struct{ st *store.Store }

func (c clientStore) InsertClient(ctx context.Context, cl store.ClientApplication) error {
	return c.st.Tx(ctx, store.Scope{TenantID: cl.TenantID}, func(tx pgx.Tx) error { return store.InsertClient(ctx, tx, cl) })
}
func (c clientStore) ListClients(ctx context.Context, tid string) (out []store.ClientApplication, err error) {
	err = c.st.Tx(ctx, store.Scope{TenantID: tid}, func(tx pgx.Tx) error { out, err = store.ListClients(ctx, tx, tid); return err })
	return
}

// buildDirectory wires the LDAP directory import (feature 016): target
// policy → policy-dialing client → directory service. Nothing is built when
// directory.enabled is false.
func (a *App) buildDirectory() error {
	cfg := a.Cfg.Directory
	if !cfg.Enabled {
		return nil
	}
	// ldapdir caps BER packets in init(); refuse to start if anything reset it.
	if ber.MaxPacketLengthBytes != ldapdir.MaxBERPacketBytes {
		return fmt.Errorf("app: ldap BER packet cap is %d, want %d", ber.MaxPacketLengthBytes, ldapdir.MaxBERPacketBytes)
	}
	pol, err := ldapdir.NewTargetPolicy(cfg.Targets)
	if err != nil {
		return err
	}
	a.Directories = directory.New(directory.Deps{Store: directorydb.DBStore{St: a.Store}, Directory: ldapdir.NewClient(pol), Envelope: a.Envelope,
		Policy: pol, Config: cfg, Cache: a.Cache, Audit: a.Audit})
	return nil
}

// activeTenantIDs lists tenants a service may register permissions for.
func (a *App) activeTenantIDs(ctx context.Context) ([]string, error) {
	var ids []string
	err := a.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		tenants, err := store.ListTenants(ctx, tx)
		if err != nil {
			return err
		}
		for _, t := range tenants {
			if t.Status == "active" {
				ids = append(ids, t.ID)
			}
		}
		return nil
	})
	return ids, err
}

// profiles enriches GET /api/v1/session from the database.
type profiles struct{ st *store.Store }

func (p profiles) Profile(ctx context.Context, tenantID, userID string) (httpapi.Profile, error) {
	var out httpapi.Profile
	err := p.st.Tx(ctx, store.Scope{TenantID: tenantID}, func(tx pgx.Tx) error {
		u, err := store.GetUser(ctx, tx, tenantID, userID)
		if err != nil {
			return err
		}
		t, err := store.GetTenant(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		pol, err := tenant.ParsePolicy(t.Policy, t.Kind == "platform")
		if err != nil {
			return err
		}
		out = httpapi.Profile{Email: u.Email, DisplayName: u.DisplayName, FirstName: u.FirstName, LastName: u.LastName, AvatarURL: tenantctx.AvatarURL(u.ID, u.AvatarID),
			MFAEnabled: u.MFAEnabled, MFARequired: pol.MFARequired, TenantSlug: t.Slug, TenantName: t.DisplayName}
		return nil
	})
	return out, err
}

// Run serves until ctx is done; background workers stop with it.
func (a *App) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.Outbox.Run(wctx, 5*time.Second)
	go a.Ring.Run(wctx, time.Minute, func(err error) { a.Log.Error("key rotation", "err", err) })
	if a.Cfg.Gateway.Enabled {
		// Gateway mode: seed console permissions and keep the gateway lease.
		go a.runGatewayMode(wctx)
	}
	return a.Freya.Run(ctx)
}

// Close releases everything Build acquired (idempotent, reverse order).
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

// notificationConn is the mesh connection to notification. The outbox is
// built before the Freya app and asks for it on its first delivery.
func (a *App) notificationConn(ctx context.Context) (grpc.ClientConnInterface, error) {
	if a.Freya == nil {
		return nil, errors.New("app: freya runtime not built yet")
	}
	return a.Freya.Client(ctx, notifyclient.Service)
}

// onEmailGivenUp reports a retired outbox message once: a warning and an
// email_given_up audit event in the message's tenant.
func (a *App) onEmailGivenUp(g email.GiveUp) {
	a.Log.Warn("email given up", "id", g.ID, "tenant", g.TenantID, "kind", g.Kind, "attempts", g.Attempts, "reason", g.Reason)
	_ = a.Audit.Emit(emailGivenUpEvent(g))
}

// emailGivenUpEvent names the outbox row, never the recipient or the link.
func emailGivenUpEvent(g email.GiveUp) audit.Event {
	return audit.Event{Type: audit.EmailGivenUp, TenantID: g.TenantID, ActorKind: "system", Outcome: "failed", Reason: "delivery_failed",
		SubjectKind: "email", SubjectID: g.ID, Details: map[string]any{"kind": g.Kind, "attempts": g.Attempts, "error": g.Reason}}
}

func (a *App) onRefusal(r tenantctx.Refusal) {
	_ = a.Audit.Emit(audit.Event{Type: audit.CrossTenantRefused, TenantID: r.TargetTenant, ActorKind: string(r.Actor.Kind), ActorUserID: r.Actor.UserID,
		ActorService: r.Actor.ServiceID, Outcome: "refused", Reason: r.Reason, Details: map[string]any{"actor_tenant": r.ActorTenant}})
}

// BootstrapResult reports what Bootstrap created or found.
type BootstrapResult struct {
	TenantID           string `json:"tenant_id"`
	InvitationID       string `json:"invitation_id"`
	AcceptURL          string `json:"accept_url"`
	KID                string `json:"kid"`
	Created            bool   `json:"tenant_created"`
	Reused             bool   `json:"invitation_reused,omitempty"`
	AlreadyProvisioned bool   `json:"already_provisioned,omitempty"`
}

var builtinRoles = []string{"owner", "admin", "operator"}

// Bootstrap ensures the platform tenant, its builtin roles, an active signing
// key and queues an operator invitation (the accept link is also returned so
// a deployment without email can complete it).
func (a *App) Bootstrap(ctx context.Context, operatorEmail string) (BootstrapResult, error) {
	if operatorEmail == "" {
		return BootstrapResult{}, errors.New("bootstrap: operator email required")
	}
	var res BootstrapResult
	var tuples []authz.Tuple
	now := store.Now()
	err := a.Store.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		t, err := store.GetTenantBySlug(ctx, tx, PlatformTenantSlug)
		if errors.Is(err, store.ErrNotFound) {
			t = store.Tenant{ID: PlatformTenantID, Slug: PlatformTenantSlug, DisplayName: "Platform", Status: "active", Kind: "platform", Policy: []byte("{}")}
			if err = store.InsertTenant(ctx, tx, t); err != nil {
				return err
			}
			res.Created = true
		} else if err != nil {
			return err
		}
		res.TenantID = t.ID
		existing, err := store.ListRoles(ctx, tx, t.ID)
		if err != nil {
			return err
		}
		roleIDs := map[string]string{}
		for _, r := range existing {
			roleIDs[r.Slug] = r.ID
		}
		for _, slug := range builtinRoles {
			if _, ok := roleIDs[slug]; ok {
				continue
			}
			r := store.Role{ID: store.NewID(), TenantID: t.ID, Slug: slug, DisplayName: slug, Builtin: true}
			if err := store.InsertRole(ctx, tx, r); err != nil {
				return err
			}
			roleIDs[slug] = r.ID
			tuples = append(tuples, authz.RoleTenantTuple(t.ID, slug))
		}
		// Idempotent operator invitation: if an operator already accepted, do
		// nothing; if a usable invitation is still outstanding, reuse it (rotate
		// its token so the returned link is current) instead of inserting a
		// duplicate and emailing again; otherwise create a fresh one + email.
		opCount, err := store.CountUsersWithRole(ctx, tx, t.ID, "operator")
		if err != nil {
			return err
		}
		switch {
		case opCount > 0:
			res.AlreadyProvisioned = true
		default:
			existing, err := store.PendingInvitationByEmail(ctx, tx, t.ID, operatorEmail)
			switch {
			case err == nil:
				tok, err := crypto.RandomToken(32)
				if err != nil {
					return err
				}
				if err := store.RotateInvitationToken(ctx, tx, t.ID, existing.ID, crypto.HashToken(tok), now.Add(7*24*time.Hour)); err != nil {
					return err
				}
				res.InvitationID = existing.ID
				res.AcceptURL = a.Cfg.Issuer + httpapi.ConsolePrefix + "/invite/accept?token=" + tok
				res.Reused = true
			case errors.Is(err, store.ErrNotFound):
				tok, err := crypto.RandomToken(32)
				if err != nil {
					return err
				}
				inv := store.Invitation{ID: store.NewID(), TenantID: t.ID, Email: operatorEmail, RoleIDs: []string{roleIDs["owner"], roleIDs["operator"]},
					TokenHash: crypto.HashToken(tok), ExpiresAt: now.Add(7 * 24 * time.Hour)}
				if err := store.InsertInvitation(ctx, tx, inv); err != nil {
					return err
				}
				res.InvitationID = inv.ID
				res.AcceptURL = a.Cfg.Issuer + httpapi.ConsolePrefix + "/invite/accept?token=" + tok
				blob, err := a.Outbox.Encode(operatorEmail, operatorInvitePayload(res.AcceptURL, t.DisplayName))
				if err != nil {
					return err
				}
				if err := store.EnqueueOutbox(ctx, tx, store.OutboxItem{ID: store.NewID(), TenantID: t.ID, Kind: "invite", ToEmail: operatorEmail, PayloadEnc: blob, NextAttemptAt: now}); err != nil {
					return err
				}
			default:
				return err
			}
		}
		keys, err := store.ListSigningKeys(ctx, tx)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.State == token.StateActive {
				res.KID = k.KID
			}
		}
		if res.KID == "" {
			k, err := token.GenerateKey(a.Envelope, now)
			if err != nil {
				return err
			}
			if err := store.InsertSigningKey(ctx, tx, k); err != nil {
				return err
			}
			res.KID = k.KID
		}
		return nil
	})
	if err != nil {
		return BootstrapResult{}, err
	}
	sys := tenantctx.WithActor(ctx, tenantctx.Actor{Kind: tenantctx.KindSystem})
	if len(tuples) > 0 {
		if err := a.Authz.Write(sys, res.TenantID, tuples, nil); err != nil {
			return BootstrapResult{}, err
		}
	}
	if res.Created {
		_ = a.Audit.Emit(audit.Event{Type: audit.TenantCreated, TenantID: res.TenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "tenant", SubjectID: res.TenantID})
	}
	if res.InvitationID != "" {
		_ = a.Audit.Emit(audit.Event{Type: audit.InviteCreated, TenantID: res.TenantID, ActorKind: "system", Outcome: "ok", SubjectKind: "invite", SubjectID: res.InvitationID})
	}
	return res, nil
}
