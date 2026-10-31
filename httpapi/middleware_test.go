package httpapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/httpapi"
)

const (
	testJSONRenderer    = "json"
	testScopeRead       = "read"
	testBearerToken     = "Bearer token"
	testClientID        = "client"
	testUnavailableCode = "verification_unavailable"
	testCustomRenderer  = "custom"
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
	return api.Principal{ClientID: testClientID, CredentialID: "grant", Scopes: []string{testScopeRead}}, s.err
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
		{"multiple spaces", []string{"Bearer  token"}, nil, 204, 1},
		{"tab separator", []string{"Bearer\ttoken"}, nil, 401, 0},
		{"token tab", []string{"Bearer token\t"}, nil, 401, 0},
		{"empty token", []string{"Bearer   "}, nil, 401, 0},
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
				if !ok || p.ClientID != testClientID {
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

type failureCase struct {
	name, header, code, challenge string
	err                           error
	status                        int
	nilAuth                       bool
}

func TestMiddlewareFailureRendering(t *testing.T) {
	for _, tc := range []failureCase{
		{name: "missing", code: "unauthorized", status: 401, challenge: `Bearer realm="api"`},
		{
			name: "malformed", header: "Bearer token extra", code: "invalid_token", status: 401,
			challenge: `Bearer realm="api", error="invalid_token"`,
		},
		{
			name: "invalid", header: testBearerToken, err: fmt.Errorf("private: %w", api.ErrUnauthorized),
			code: "invalid_token", status: 401, challenge: `Bearer realm="api", error="invalid_token"`,
		},
		{
			name: "scope", header: testBearerToken, err: fmt.Errorf("private: %w", api.ErrForbidden),
			code: "insufficient_scope", status: 403, challenge: `Bearer realm="api", error="insufficient_scope"`,
		},
		{
			name: "unavailable", header: testBearerToken, err: fmt.Errorf("private: %w", api.ErrUnavailable),
			code: testUnavailableCode, status: 503,
		},
		{
			name: "unexpected", header: testBearerToken, err: errors.New("private database failure"),
			code: testUnavailableCode, status: 503,
		},
		{name: "nil verifier", code: testUnavailableCode, status: 503, nilAuth: true},
	} {
		for _, renderer := range []string{"default", testJSONRenderer, testCustomRenderer} {
			t.Run(tc.name+"/"+renderer, func(t *testing.T) { testFailureRenderer(t, tc, renderer) })
		}
	}
}

func testFailureRenderer(t *testing.T, tc failureCase, renderer string) {
	t.Helper()
	var auth httpapi.Authenticator = &stub{err: tc.err}
	if tc.nilAuth {
		auth = nil
	}
	options := httpapi.Options{}
	customCalls := 0
	switch renderer {
	case testJSONRenderer:
		options.ErrorHandler = httpapi.JSONErrorHandler
	case testCustomRenderer:
		options.ErrorHandler = func(w http.ResponseWriter, r *http.Request, failure httpapi.Error) {
			customCalls++
			assertCustomFailure(t, w, r, failure, tc)
			w.WriteHeader(failure.Status)
			_, _ = w.Write([]byte(testCustomRenderer))
		}
	}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("failure reached handler") })
	handler := httpapi.MiddlewareWithOptions(auth, options, testScopeRead)(next)
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.test/protected", nil)
	if tc.header != "" {
		req.Header.Set("Authorization", tc.header)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != tc.status || w.Header().Get("WWW-Authenticate") != tc.challenge {
		t.Fatalf("status=%d challenge=%q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	assertFailureBody(t, w, tc, renderer, customCalls)
}

func assertCustomFailure(t *testing.T, w http.ResponseWriter, r *http.Request, failure httpapi.Error, tc failureCase) {
	t.Helper()
	if failure.Status != tc.status || failure.Code != tc.code {
		t.Fatalf("failure=%+v", failure)
	}
	if w.Header().Get("WWW-Authenticate") != tc.challenge {
		t.Fatal("challenge not set before custom handler")
	}
	if r.URL.Path != "/protected" {
		t.Fatal("request not forwarded")
	}
}

func assertFailureBody(t *testing.T, w *httptest.ResponseRecorder, tc failureCase, renderer string, customCalls int) {
	t.Helper()
	switch renderer {
	case testJSONRenderer:
		if w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\""+tc.code+"\"}\n" {
			t.Fatalf("JSON response: %v %q", w.Header(), w.Body.String())
		}
	case testCustomRenderer:
		if customCalls != 1 || w.Body.String() != testCustomRenderer {
			t.Fatalf("calls=%d body=%q", customCalls, w.Body.String())
		}
	default:
		want := "unauthorized\n"
		switch tc.status {
		case http.StatusForbidden:
			want = "forbidden\n"
		case http.StatusServiceUnavailable:
			want = "verification unavailable\n"
		}
		if w.Body.String() != want {
			t.Fatalf("body=%q want=%q", w.Body.String(), want)
		}
	}
}

func TestMiddlewareSpaceBudget(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		spaces, tokenSize, status int
	}{
		{"two spaces at bound", 2, 255, 204},
		{"two spaces over bound", 2, 256, 401},
		{"many spaces at bound", 256, 1, 204},
		{"many spaces over bound", 257, 1, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := strings.Repeat("x", tc.tokenSize)
			auth := &stub{token: token}
			req := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.test/", nil)
			req.Header.Set("Authorization", "Bearer"+strings.Repeat(" ", tc.spaces)+token)
			w := httptest.NewRecorder()
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
			httpapi.Middleware(auth, testScopeRead)(next).ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			wantCalls := 0
			if tc.status == 204 {
				wantCalls = 1
			}
			if auth.calls != wantCalls {
				t.Fatalf("calls=%d want=%d", auth.calls, wantCalls)
			}
		})
	}
}

func TestMiddlewareDoesNotReadAlternateTokenSources(t *testing.T) {
	auth := &stub{}
	req := httptest.NewRequestWithContext(
		t.Context(), "POST", "https://example.test/?token=token&access_token=token", strings.NewReader("access_token=token"),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name: "access_token", Value: "token", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	w := httptest.NewRecorder()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("alternate source accepted") })
	httpapi.Middleware(auth, testScopeRead)(next).ServeHTTP(w, req)
	if w.Code != 401 || auth.calls != 0 || w.Header().Get("WWW-Authenticate") != `Bearer realm="api"` {
		t.Fatalf("status=%d calls=%d headers=%v", w.Code, auth.calls, w.Header())
	}
}

type authenticatorFunc func(context.Context, string, ...string) (api.Principal, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, token string, scopes ...string) (api.Principal, error) {
	return f(ctx, token, scopes...)
}

func TestMiddlewareClonesScopesAndPrincipal(t *testing.T) {
	required := []string{testScopeRead}
	shared := api.Principal{ClientID: testClientID, Scopes: []string{testScopeRead}}
	auth := authenticatorFunc(func(_ context.Context, _ string, scopes ...string) (api.Principal, error) {
		if len(scopes) != 1 || scopes[0] != testScopeRead {
			t.Fatalf("scopes=%v", scopes)
		}
		return shared, nil
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shared.Scopes[0] = "changed by verifier owner"
		p, ok := httpapi.Principal(r.Context())
		if !ok || p.Scopes[0] != testScopeRead {
			t.Fatalf("principal=%+v ok=%v", p, ok)
		}
		p.Scopes[0] = "changed by caller"
		again, _ := httpapi.Principal(r.Context())
		if again.Scopes[0] != testScopeRead {
			t.Fatal("principal aliases accessor result")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := httpapi.MiddlewareWithOptions(auth, httpapi.Options{}, required...)(next)
	required[0] = "changed after construction"
	req := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.test/", nil)
	req.Header.Set("Authorization", testBearerToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}
