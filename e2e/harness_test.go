//go:build e2e

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/jackc/pgx/v5/pgxpool"
)

const propagationBudget = 4 * time.Second

type harness struct {
	ctx       context.Context
	binary    string
	dsn       string
	container string
	pool      *pgxpool.Pool
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn, container, runID := os.Getenv("API_E2E_DATABASE_URL"), os.Getenv("API_E2E_CONTAINER"), os.Getenv("API_E2E_RUN_ID")
	if dsn == "" || container == "" || runID == "" {
		t.Fatal("run make e2e: this suite requires its own disposable Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	h := &harness{ctx: ctx, dsn: dsn, container: container}
	label, err := exec.CommandContext(ctx, "docker", "inspect", "--format", `{{ index .Config.Labels "api.e2e" }}`, container).Output()
	if err != nil || strings.TrimSpace(string(label)) != runID {
		t.Fatal("refusing fault injection: database container ownership was not verified")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	h.binary = filepath.Join(t.TempDir(), "access")
	build := exec.CommandContext(ctx, "go", "build", "-race", "-o", h.binary, "./examples/access")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example: %v\n%s", err, output)
	}
	h.pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("cannot configure isolated database pool")
	}
	t.Cleanup(h.pool.Close)
	return h
}

func (h *harness) docker(t *testing.T, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", args...).Run(); err != nil {
		t.Fatalf("Docker %s failed: %v", args[0], err)
	}
}

func (h *harness) databaseReady(t *testing.T) {
	t.Helper()
	eventually(t, 15*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(h.ctx, time.Second)
		defer cancel()
		return h.pool.Ping(ctx) == nil
	})
}

type fixture struct {
	h      *harness
	schema string
	mu     sync.Mutex
	tokens []string
}

func (h *harness) fixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{h: h, schema: "api_e2e_" + strings.ToLower(rand.Text())}
	f.mustCLI(t, "migrate")
	f.mustCLI(t, "migrate") // Repeat application must preserve the schema.
	return f
}

func (f *fixture) env(app string) []string {
	env := make([]string, 0, len(os.Environ())+3)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "API_DATABASE_URL=") || strings.HasPrefix(entry, "API_SCHEMA=") || strings.HasPrefix(entry, "GORACE=") {
			continue
		}
		env = append(env, entry)
	}
	dsn, _ := url.Parse(f.h.dsn)
	query := dsn.Query()
	query.Set("application_name", app)
	dsn.RawQuery = query.Encode()
	// CLI commands terminate frequently. Keep race detection without its
	// default one-second exit delay; any race makes the process fail.
	return append(env, "API_DATABASE_URL="+dsn.String(), "API_SCHEMA="+f.schema, "GORACE=halt_on_error=1 atexit_sleep_ms=0")
}

type cliResult struct {
	output     []byte
	stderr     string
	err        error
	contextErr error
}

func (r cliResult) rejected() bool {
	var exit *exec.ExitError
	// Expected CLI errors exit 1. A deadline, signal, panic or race detector
	// must fail the test instead of masquerading as a valid rejection.
	return r.contextErr == nil && errors.As(r.err, &exit) && exit.ExitCode() == 1
}

func (f *fixture) cli(args ...string) cliResult {
	ctx, cancel := context.WithTimeout(f.h.ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.h.binary, args...)
	cmd.Env = f.env("api_e2e_admin")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return cliResult{output: stdout.Bytes(), stderr: stderr.String(), err: err, contextErr: ctx.Err()}
}

func (f *fixture) mustCLI(t *testing.T, args ...string) []byte {
	t.Helper()
	r := f.cli(args...)
	if r.err != nil {
		// Successful issuance stdout contains secrets, so never dump it.
		t.Fatalf("CLI %s failed: %v (output withheld)", args[0], r.err)
	}
	if r.stderr != "" {
		t.Fatalf("CLI %s unexpectedly wrote diagnostics (output withheld)", args[0])
	}
	return r.output
}

func (f *fixture) deniedCLI(t *testing.T, category string, args ...string) {
	t.Helper()
	r := f.cli(args...)
	if !r.rejected() || len(r.output) != 0 || !strings.Contains(r.stderr, "api: "+category) {
		t.Fatalf("CLI %s did not reject atomically as %s (output withheld)", args[0], category)
	}
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal("invalid CLI/HTTP JSON (contents withheld)")
	}
	return value
}

func (f *fixture) client(t *testing.T, scopes string) api.Client {
	t.Helper()
	return decode[api.Client](t, f.mustCLI(t, "create-client", "-name", "e2e-client", "-scopes", scopes))
}

func (f *fixture) issued(t *testing.T, raw []byte) api.Issued {
	t.Helper()
	issued := decode[api.Issued](t, raw)
	if len(issued.Token) != 81 || issued.Credential.ID == "" || issued.ExpiresAt.IsZero() {
		t.Fatal("incomplete issue result (contents withheld)")
	}
	f.mu.Lock()
	f.tokens = append(f.tokens, issued.Token)
	f.mu.Unlock()
	return issued
}

func (f *fixture) issue(t *testing.T, client api.Client, scopes, ttl string) api.Issued {
	t.Helper()
	return f.issued(t, f.mustCLI(t, "issue", "-client", client.ID, "-name", "e2e-key", "-scopes", scopes, "-ttl", ttl))
}

func (f *fixture) rotate(t *testing.T, previous api.Issued, grace string) api.Issued {
	t.Helper()
	return f.issued(t, f.mustCLI(t, "rotate", "-credential", previous.Credential.ID, "-generation", fmt.Sprint(previous.Credential.Generation), "-grace", grace, "-ttl", "1h"))
}

func (f *fixture) noSecrets(t *testing.T, output string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, token := range f.tokens {
		if strings.Contains(output, token) {
			t.Fatal("secret leaked outside the administrative issue response (contents withheld)")
		}
	}
}

type server struct {
	f       *fixture
	address string
	app     string
	client  *http.Client
}

func (f *fixture) server(t *testing.T, mode string, staleness, refresh time.Duration) *server {
	t.Helper()
	app := "api_e2e_" + strings.ToLower(rand.Text())
	cmd := exec.CommandContext(f.h.ctx, f.h.binary, "serve", "-addr", "127.0.0.1:0", "-cache", mode, "-max-staleness", staleness.String(), "-refresh", refresh.String())
	cmd.Env = f.env(app)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("cannot start HTTP process")
	}
	ready := make(chan string, 1)
	readDone := make(chan struct{})
	var diagnostics strings.Builder
	var readErr error
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			diagnostics.WriteString(line + "\n")
			if address, ok := strings.CutPrefix(line, "listening on "); ok {
				select {
				case ready <- address:
				default:
				}
			}
		}
		readErr = scanner.Err()
	}()
	done := make(chan struct{})
	var processErr error
	go func() {
		// Wait closes StderrPipe; finish reading first so shutdown diagnostics
		// cannot be silently dropped before the secret and race checks.
		<-readDone
		processErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("HTTP process did not shut down gracefully")
		}
		<-readDone
		if readErr != nil {
			t.Error("HTTP diagnostics could not be read completely")
		}
		f.noSecrets(t, stdout.String())
		f.noSecrets(t, diagnostics.String())
		if processErr != nil {
			t.Errorf("HTTP process failed: %v (diagnostics withheld)", processErr)
		}
	})
	s := &server{f: f, app: app, client: &http.Client{Timeout: 3 * time.Second}}
	t.Cleanup(s.client.CloseIdleConnections)
	select {
	case s.address = <-ready:
	case <-done:
		t.Fatal("HTTP process exited before readiness (diagnostics withheld)")
	case <-time.After(10 * time.Second):
		t.Fatal("HTTP process readiness timed out")
	}
	if !strings.HasPrefix(s.address, "http://127.0.0.1:") {
		t.Fatal("HTTP process did not bind to loopback")
	}
	s.expect(t, "", http.StatusUnauthorized)
	if mode != "strict" {
		eventually(t, propagationBudget, func() bool {
			var listening bool
			err := f.h.pool.QueryRow(f.h.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND query LIKE 'LISTEN %' AND state='idle')`, app).Scan(&listening)
			return err == nil && listening
		})
	}
	return s
}

func (s *server) request(t *testing.T, token string, mutate func(*http.Request)) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(s.f.h.ctx, http.MethodGet, s.address+"/orders", nil)
	if err != nil {
		t.Fatal("invalid test request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if mutate != nil {
		mutate(req)
	}
	response, err := s.client.Do(req)
	if err != nil {
		// url.Error may include a token from a deliberately rejected query.
		t.Fatal("HTTP request did not return a response (URL withheld)")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		t.Fatal("cannot read HTTP response")
	}
	s.f.noSecrets(t, string(body))
	switch response.StatusCode {
	case http.StatusUnauthorized:
		if response.Header.Get("WWW-Authenticate") == "" || string(body) != "unauthorized\n" {
			t.Fatal("invalid authentication error response (contents withheld)")
		}
	case http.StatusForbidden:
		if string(body) != "forbidden\n" {
			t.Fatal("invalid scope error response (contents withheld)")
		}
	case http.StatusServiceUnavailable:
		if string(body) != "verification unavailable\n" {
			t.Fatal("infrastructure details leaked in HTTP response (contents withheld)")
		}
	}
	return response.StatusCode, body
}

func (s *server) expect(t *testing.T, token string, want int) []byte {
	t.Helper()
	status, body := s.request(t, token, nil)
	if status != want {
		t.Fatalf("HTTP status=%d, want %d", status, want)
	}
	return body
}

func (s *server) eventually(t *testing.T, token string, want int, budget time.Duration) {
	t.Helper()
	last := 0
	deadline := time.Now().Add(budget)
	for {
		last, _ = s.request(t, token, nil)
		if last == want {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("HTTP did not become %d within %s; last=%d", want, budget, last)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func eventually(t *testing.T, budget time.Duration, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for !predicate() {
		if !time.Now().Before(deadline) {
			t.Fatalf("condition not reached within %s", budget)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
