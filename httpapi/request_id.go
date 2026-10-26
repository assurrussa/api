package httpapi

import (
	"context"
	"crypto/rand"
	"net/http"
	"strings"
)

const (
	// RequestIDHeader carries diagnostic correlation, never authorization or idempotency.
	RequestIDHeader = "X-Request-ID"
	// MaxRequestIDLength bounds caller-controlled diagnostic metadata.
	MaxRequestIDLength = 128
)

type requestIDKey struct{}

// NewRequestID creates an opaque random ID for one newly created HTTP request.
// Explicit client retries should create a new ID. Transparent transport replays
// may retain it; this is not an identifier for every physical network attempt.
func NewRequestID() string { return rand.Text() }

// ValidRequestID accepts 1..128 ASCII letters, digits, dots, underscores or hyphens.
// A valid ID is still untrusted metadata, not proof of identity or uniqueness.
func ValidRequestID(id string) bool {
	if len(id) == 0 || len(id) > MaxRequestIDLength {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ResolveRequestID preserves exactly one safe header value, otherwise generates
// a replacement. Pass all values: duplicate and comma-joined headers are unsafe.
// It never rejects a request or returns the rejected input for logging.
func ResolveRequestID(values []string) string {
	if len(values) == 1 && ValidRequestID(values[0]) {
		return values[0]
	}
	return NewRequestID()
}

// WithRequestID attaches safe diagnostic metadata without changing principal state.
// Missing or unsafe IDs are replaced. Use RequestID to obtain the resolved value.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, ResolveRequestID([]string{id}))
}

// RequestID returns the diagnostic ID, or an empty string when not installed.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// RequestIDMiddleware is opt-in and independent of authentication. Install it
// outside Middleware to echo IDs on authentication failures as well as success.
// It sets a safe request header, context value and response header before calling
// next, without changing the caller's request, body, identity or Idempotency-Key.
// Downstream handlers must preserve the response header. The host owns logging
// and panic recovery; this middleware does not log headers, URLs or bodies.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestHeaderID(r.Header)
		request := r.Clone(WithRequestID(r.Context(), id))
		if request.Header == nil {
			request.Header = make(http.Header)
		}
		for key := range request.Header {
			if strings.EqualFold(key, RequestIDHeader) {
				delete(request.Header, key)
			}
		}
		request.Header.Set(RequestIDHeader, id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, request)
	})
}

// Include noncanonical map keys from other middleware as well as parsed headers.
func requestHeaderID(header http.Header) string {
	var values []string
	found := false
	for key, candidate := range header {
		if !strings.EqualFold(key, RequestIDHeader) {
			continue
		}
		if found || len(candidate) != 1 {
			return NewRequestID()
		}
		found, values = true, candidate
	}
	return ResolveRequestID(values)
}
