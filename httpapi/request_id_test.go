package httpapi_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/httpapi"
)

func TestResolveRequestID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		values   []string
		preserve bool
	}{
		{"absent value", nil, false},
		{"empty", []string{""}, false},
		{"allowed alphabet", []string{"abc.ABC_123-xyz"}, true},
		{"limit", []string{strings.Repeat("a", httpapi.MaxRequestIDLength)}, true},
		{"too long", []string{strings.Repeat("a", httpapi.MaxRequestIDLength+1)}, false},
		{"repeated header", []string{"safe", "safe"}, false},
		{"joined", []string{"one,two"}, false},
		{"space", []string{" a "}, false},
		{"newline", []string{"a\r\nb"}, false},
		{"tab", []string{"a\tb"}, false},
		{"nul", []string{"a\x00b"}, false},
		{"unicode", []string{"запрос"}, false},
		{"quote", []string{"a\"b"}, false},
		{"slash", []string{"a/b"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.values)
			id := httpapi.ResolveRequestID(tc.values)
			if !httpapi.ValidRequestID(id) || !slices.Equal(before, tc.values) {
				t.Fatal("unsafe result or mutated input")
			}
			if tc.preserve && id != tc.values[0] {
				t.Fatal("safe ID was replaced")
			}
			if !tc.preserve && slices.Contains(tc.values, id) {
				t.Fatal("unsafe ID was preserved")
			}
		})
	}
}

func TestRequestIDContextAndFreshAttempts(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	if httpapi.RequestID(parent) != "" {
		t.Fatal("unexpected default ID")
	}
	seen := map[string]bool{}
	for range 100 {
		id := httpapi.NewRequestID()
		if !httpapi.ValidRequestID(id) || seen[id] {
			t.Fatal("invalid or repeated generated ID")
		}
		seen[id] = true
		ctx := httpapi.WithRequestID(parent, id)
		if httpapi.RequestID(ctx) != id || httpapi.RequestID(parent) != "" {
			t.Fatal("context isolation failed")
		}
	}
	ctx := httpapi.WithRequestID(parent, "unsafe\n")
	cancel()
	if !httpapi.ValidRequestID(httpapi.RequestID(ctx)) || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("context normalization or cancellation lost")
	}
}

func TestRequestIDMiddlewarePreservesRequest(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/document", strings.NewReader("unchanged body"))
	r.Header.Add(httpapi.RequestIDHeader, "unsafe")
	r.Header.Add(httpapi.RequestIDHeader, "second-value")
	r.Header.Set("Authorization", testBearerToken)
	r.Header.Set("Idempotency-Key", "stable-operation")
	r.Header.Set("If-Match", `"stable-version"`)
	original := r.Header.Clone()
	w := httptest.NewRecorder()
	httpapi.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, next *http.Request) {
		id := httpapi.RequestID(next.Context())
		if !httpapi.ValidRequestID(id) || next.Header.Get(httpapi.RequestIDHeader) != id ||
			len(next.Header.Values(httpapi.RequestIDHeader)) != 1 || w.Header().Get(httpapi.RequestIDHeader) != id {
			t.Fatal("request, context and response correlation differ")
		}
		for _, key := range []string{"Authorization", "Idempotency-Key", "If-Match"} {
			if next.Header.Get(key) != original.Get(key) {
				t.Fatal("identity or precondition changed")
			}
		}
		body, err := io.ReadAll(next.Body)
		if err != nil || string(body) != "unchanged body" {
			t.Fatal("request body changed")
		}
		w.WriteHeader(http.StatusConflict)
	})).ServeHTTP(w, r)
	if w.Code != http.StatusConflict || httpapi.RequestID(r.Context()) != "" ||
		!slices.Equal(r.Header.Values(httpapi.RequestIDHeader), original.Values(httpapi.RequestIDHeader)) {
		t.Fatal("caller request changed or error response lost")
	}
}

func TestRequestIDMiddlewareWithAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		auth   httpapi.Authenticator
		header string
		status int
	}{
		{"success", &stub{}, testBearerToken, http.StatusNoContent},
		{"missing token", &stub{}, "", http.StatusUnauthorized},
		{"unauthorized", &stub{err: api.ErrUnauthorized}, testBearerToken, http.StatusUnauthorized},
		{"forbidden", &stub{err: api.ErrForbidden}, testBearerToken, http.StatusForbidden},
		{"unavailable", nil, testBearerToken, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, ok := httpapi.Principal(r.Context())
				if !ok || p.ClientID == "" || httpapi.RequestID(r.Context()) != "test-request" {
					t.Fatal("principal or request context lost")
				}
				w.WriteHeader(http.StatusNoContent)
			})
			auth := httpapi.Middleware(tc.auth, testScopeRead)(next)
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.Header.Set("Authorization", tc.header)
			r.Header.Set(httpapi.RequestIDHeader, "test-request")
			w := httptest.NewRecorder()
			httpapi.RequestIDMiddleware(auth).ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get(httpapi.RequestIDHeader) != "test-request" {
				t.Fatal("status or echo differs")
			}
		})
	}
}

func TestAuthenticationDoesNotOptIntoRequestIDs(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	httpapi.Middleware(nil)(http.NotFoundHandler()).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get(httpapi.RequestIDHeader) != "" {
		t.Fatal("existing authentication defaults changed")
	}
}

func TestRequestIDMiddlewareHeaderCasesAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		want   string
	}{
		{"nil header map", nil, ""},
		{"lowercase map", http.Header{"x-request-id": {"lower-id"}}, "lower-id"},
		{"mixed duplicates", http.Header{"X-Request-Id": {"first"}, "x-request-id": {"second"}}, ""},
		{"empty values", http.Header{"X-Request-Id": nil}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			r.Header = tc.header
			// A stale/invalid parent correlation must not override the wire value.
			r = r.WithContext(httpapi.WithRequestID(r.Context(), "parent-id"))
			w := httptest.NewRecorder()
			panicking := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				id := httpapi.RequestID(r.Context())
				if !httpapi.ValidRequestID(id) || id == "parent-id" ||
					len(r.Header) != 1 || r.Header.Get(httpapi.RequestIDHeader) != id {
					t.Fatal("header normalization or context replacement failed")
				}
				panic("synthetic handler failure")
			})
			// Host recovery outside correlation retains the already-set response ID.
			func() {
				defer func() {
					if recover() != nil {
						w.WriteHeader(http.StatusInternalServerError)
					}
				}()
				httpapi.RequestIDMiddleware(panicking).ServeHTTP(w, r)
			}()
			id := w.Header().Get(httpapi.RequestIDHeader)
			if w.Code != http.StatusInternalServerError || !httpapi.ValidRequestID(id) ||
				(tc.want != "" && id != tc.want) {
				t.Fatal("recovery lost response correlation")
			}
		})
	}
}
