// Package httpapi adapts API credential verification to net/http.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/assurrussa/api"
)

type Authenticator interface {
	Authenticate(ctx context.Context, token string, scopes ...string) (api.Principal, error)
}
type principalKey struct{}

// Error describes a public HTTP authentication failure. It never contains the
// underlying verifier error or credential data.
type Error struct {
	Status int
	Code   string
}

// Options controls how middleware failures are rendered.
type Options struct {
	// ErrorHandler writes the response body and status. The middleware sets the
	// required WWW-Authenticate challenge before calling it. Nil uses text bodies.
	ErrorHandler func(http.ResponseWriter, *http.Request, Error)
}

// JSONErrorHandler renders the public failure code as {"error":"code"}.
func JSONErrorHandler(w http.ResponseWriter, _ *http.Request, failure Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(failure.Status)
	if err := json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: failure.Code}); err != nil {
		// The response has started; a failed write cannot be replaced safely.
		return
	}
}

// Principal returns a copy of the verified principal, never caller-mutable cache state.
func Principal(ctx context.Context) (api.Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(api.Principal)
	principal.Scopes = slices.Clone(principal.Scopes)
	return principal, ok
}

// Middleware requires every scope. Only one Authorization header is accepted;
// tokens in URLs, cookies, or request bodies are deliberately not recognized.
// TLS termination and request-rate limits belong to the host.
func Middleware(auth Authenticator, required ...string) func(http.Handler) http.Handler {
	return MiddlewareWithOptions(auth, Options{}, required...)
}

// MiddlewareWithOptions is Middleware with an optional public error renderer.
// Bearer credentials accept one or more ASCII spaces after the scheme, within
// the same total header bound of len("Bearer ")+256 bytes.
func MiddlewareWithOptions(auth Authenticator, options Options, required ...string) func(http.Handler) http.Handler {
	scopes := slices.Clone(required)
	errorHandler := options.ErrorHandler
	if errorHandler == nil {
		errorHandler = textErrorHandler
	}
	fail := func(w http.ResponseWriter, r *http.Request, status int, code, challenge string) {
		if challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
		errorHandler(w, r, Error{Status: status, Code: code})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth == nil {
				fail(w, r, http.StatusServiceUnavailable, "verification_unavailable", "")
				return
			}
			headers := r.Header.Values("Authorization")
			if len(headers) == 0 {
				fail(w, r, http.StatusUnauthorized, "unauthorized", `Bearer realm="api"`)
				return
			}
			// Bound untrusted input before parsing to avoid allocations that grow
			// with the number of separators in a malformed header.
			if len(headers) != 1 || len(headers[0]) > len("Bearer ")+256 {
				fail(w, r, http.StatusUnauthorized, "invalid_token", `Bearer realm="api", error="invalid_token"`)
				return
			}
			scheme, token, found := strings.Cut(headers[0], " ")
			token = strings.TrimLeft(token, " ")
			if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n\v\f") {
				fail(w, r, http.StatusUnauthorized, "invalid_token", `Bearer realm="api", error="invalid_token"`)
				return
			}
			principal, err := auth.Authenticate(r.Context(), token, scopes...)
			switch {
			case errors.Is(err, api.ErrUnauthorized):
				fail(w, r, http.StatusUnauthorized, "invalid_token", `Bearer realm="api", error="invalid_token"`)
			case errors.Is(err, api.ErrForbidden):
				fail(w, r, http.StatusForbidden, "insufficient_scope", `Bearer realm="api", error="insufficient_scope"`)
			case err != nil:
				fail(w, r, http.StatusServiceUnavailable, "verification_unavailable", "")
			default:
				principal.Scopes = slices.Clone(principal.Scopes)
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
			}
		})
	}
}

func textErrorHandler(w http.ResponseWriter, _ *http.Request, failure Error) {
	message := "verification unavailable"
	switch failure.Status {
	case http.StatusUnauthorized:
		message = "unauthorized"
	case http.StatusForbidden:
		message = "forbidden"
	}
	http.Error(w, message, failure.Status)
}
