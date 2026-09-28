// Package httpapi adapts API credential verification to net/http.
package httpapi

import (
	"context"
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
	scopes := slices.Clone(required)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth == nil {
				http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
				return
			}
			headers := r.Header.Values("Authorization")
			// Bound untrusted input before parsing to avoid allocations that grow
			// with the number of separators in a malformed header.
			if len(headers) != 1 || len(headers[0]) > len("Bearer ")+256 {
				unauthorized(w)
				return
			}
			scheme, token, found := strings.Cut(headers[0], " ")
			if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.Contains(token, " ") {
				unauthorized(w)
				return
			}
			principal, err := auth.Authenticate(r.Context(), token, scopes...)
			switch {
			case errors.Is(err, api.ErrUnauthorized):
				unauthorized(w)
			case errors.Is(err, api.ErrForbidden):
				http.Error(w, "forbidden", http.StatusForbidden)
			case err != nil:
				http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
			default:
				principal.Scopes = slices.Clone(principal.Scopes)
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
			}
		})
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="api"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
