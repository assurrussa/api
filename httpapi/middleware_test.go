package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/httpapi"
)

const (
	testScopeRead   = "read"
	testBearerToken = "Bearer token"
)

type stub struct {
	err   error
	calls int
	token string
}

func (s *stub) Authenticate(_ context.Context, token string, scopes ...string) (api.Principal, error) {
	s.calls++
	want := s.token
	if want == "" {
		want = "token"
	}
	if token != want || len(scopes) != 1 || scopes[0] != testScopeRead {
		panic("wrong middleware forwarding")
	}
	return api.Principal{ClientID: "client", CredentialID: "grant", Scopes: []string{testScopeRead}}, s.err
}

func TestMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name          string
		headers       []string
		err           error
		status, calls int
	}{
		{"ok", []string{testBearerToken}, nil, 204, 1},
		{"case insensitive scheme", []string{"bearer token"}, nil, 204, 1},
		{"missing", nil, nil, 401, 0},
		{"duplicate", []string{testBearerToken, testBearerToken}, nil, 401, 0},
		{"malformed", []string{"Bearer  token"}, nil, 401, 0},
		{"extra separator", []string{"Bearer token extra"}, nil, 401, 0},
		{"trailing separator", []string{"Bearer token "}, nil, 401, 0},
		{"bad secret", []string{testBearerToken}, api.ErrUnauthorized, 401, 1},
		{"scope", []string{testBearerToken}, api.ErrForbidden, 403, 1},
		{"infrastructure", []string{testBearerToken}, errors.New("private database error"), 503, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &stub{err: tc.err}
			handler := httpapi.Middleware(auth, testScopeRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, ok := httpapi.Principal(r.Context())
				if !ok || p.ClientID != "client" {
					t.Fatal("principal missing")
				}
				p.Scopes[0] = "mutated"
				p2, _ := httpapi.Principal(r.Context())
				if p2.Scopes[0] != testScopeRead {
					t.Fatal("principal aliases context")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequestWithContext(context.Background(), "GET", "https://example.test/?token=token", nil)
			for _, v := range tc.headers {
				req.Header.Add("Authorization", v)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || auth.calls != tc.calls {
				t.Fatalf("status=%d calls=%d", w.Code, auth.calls)
			}
			if tc.status == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("missing challenge")
			}
			if tc.status == 503 && w.Body.String() != "verification unavailable\n" {
				t.Fatal("internal error leaked")
			}
		})
	}
}

func TestMiddlewareTokenLengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		name          string
		size          int
		status, calls int
	}{
		{"empty", 0, 401, 0},
		{"maximum", 256, 204, 1},
		{"oversized", 257, 401, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := strings.Repeat("x", tc.size)
			auth := &stub{token: token}
			handler := httpapi.Middleware(auth, testScopeRead)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequestWithContext(context.Background(), "GET", "https://example.test/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || auth.calls != tc.calls {
				t.Fatalf("status=%d calls=%d", w.Code, auth.calls)
			}
		})
	}
}

func TestMiddlewareOversizedHeaderAllocations(t *testing.T) {
	// Keep this test sequential: TotalAlloc measures process-wide allocations.
	auth := &stub{}
	handler := httpapi.Middleware(auth, testScopeRead)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("oversized header reached handler")
	}))
	req := httptest.NewRequestWithContext(context.Background(), "GET", "https://example.test/", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat(" ", (1<<20)-2048)+"invalid")
	w := httptest.NewRecorder()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	handler.ServeHTTP(w, req)
	runtime.ReadMemStats(&after)
	if w.Code != http.StatusUnauthorized || auth.calls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, auth.calls)
	}
	// Allow ample response overhead, but never allocate a slice per separator
	// (which previously consumed about 16 MiB for this header).
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Fatalf("oversized header allocated %d bytes, want at most 64 KiB", allocated)
	}
}
