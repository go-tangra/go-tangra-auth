package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// Error is a refusal with a stable reason from the OpenAPI closed vocabulary.
type Error struct {
	Status int
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Common refusals.
var (
	ErrUnauthenticated = &Error{http.StatusUnauthorized, "unauthenticated"}
	ErrForbidden       = &Error{http.StatusForbidden, "forbidden"}
	ErrNotFound        = &Error{http.StatusNotFound, "not_found"}
	ErrMalformed       = &Error{http.StatusBadRequest, "malformed_body"}
	ErrValidation      = &Error{http.StatusBadRequest, "validation_failed"}
	ErrNotImplemented  = &Error{http.StatusNotImplemented, "not_implemented"}
)

// MaxBodyBytes bounds JSON bodies independently of the edge limit.
const MaxBodyBytes = 64 << 10

// WriteJSON encodes v with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError emits {"reason": ...} and nothing else.
func WriteError(w http.ResponseWriter, status int, reason string) {
	WriteJSON(w, status, map[string]string{"reason": reason})
}

// Fail maps err to a response: *Error verbatim, anything else 500 "internal"
// (details go to the log only).
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	var e *Error
	if errors.As(err, &e) {
		WriteError(w, e.Status, e.Reason)
		return
	}
	if log != nil {
		log.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err)
	}
	WriteError(w, http.StatusInternalServerError, "internal")
}

// DecodeJSON reads a bounded JSON body into v, refusing unknown fields and
// trailing data.
func DecodeJSON(r *http.Request, v any) error {
	body := http.MaxBytesReader(nil, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}
