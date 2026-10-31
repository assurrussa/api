package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/jackc/pgx/v5/pgxpool"
)

type waitingAuthenticator struct {
	observed chan context.Context
}

func (a waitingAuthenticator) Authenticate(ctx context.Context, _ string, _ ...string) (api.Principal, error) {
	a.observed <- ctx
	<-ctx.Done()
	return api.Principal{}, ctx.Err()
}

func TestOrdersHandlerBoundsAuthentication(t *testing.T) {
	auth := waitingAuthenticator{observed: make(chan context.Context, 1)}
	request := httptest.NewRequest(http.MethodGet, "/orders", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	ordersHandler(auth, 10*time.Millisecond).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	ctx := <-auth.observed
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("authentication context error = %v, want deadline exceeded", ctx.Err())
	}
}

type blockingStore struct {
	api.Store
	entered chan struct{}
	release chan struct{}
	record  api.Record
}

func (st *blockingStore) Lookup(ctx context.Context, _ string) (api.Record, error) {
	select {
	case st.entered <- struct{}{}:
	default:
	}
	select {
	case <-st.release:
		return st.record, nil
	case <-ctx.Done():
		return api.Record{}, ctx.Err()
	}
}

func TestServeDrainsActiveAuthentication(t *testing.T) {
	raw := [32]byte{1, 2, 3}
	id := strings.Repeat("a", 32)
	token := "api1_" + id + "." + base64.RawURLEncoding.EncodeToString(raw[:])
	st := &blockingStore{entered: make(chan struct{}, 1), release: make(chan struct{}), record: api.Record{
		Client:     api.Client{ID: "client", Scopes: []string{"orders:read"}},
		Credential: api.Credential{ID: "credential", ClientID: "client", Scopes: []string{"orders:read"}},
		Secret:     api.SecretVersion{ID: id, CredentialID: "credential", Digest: sha256.Sum256(raw[:]), ExpiresAt: time.Now().Add(time.Hour)},
	}}
	s, err := api.New(st, api.Config{Scopes: []string{"orders:read"}, DefaultTTL: time.Hour, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	signalCtx, signalStop := context.WithCancel(context.Background())
	defer signalStop()
	serverDone := make(chan error, 1)
	listening := make(chan string, 1)
	go func() {
		serverDone <- startAndServe(signalCtx, s, func() error {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			listening <- listener.Addr().String()
			return serveListener(signalCtx, listener, s)
		})
	}()
	var addr string
	select {
	case addr = <-listening:
	case err := <-serverDone:
		t.Fatalf("server did not listen: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not listen")
	}
	request, err := http.NewRequest(http.MethodGet, "http://"+addr+"/orders", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	responseDone := make(chan int, 1)
	go func() {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Do(request)
		if err != nil {
			responseDone <- 0
			return
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		responseDone <- response.StatusCode
	}()
	select {
	case <-st.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("authentication did not start")
	}
	signalStop()
	close(st.release)
	select {
	case status := <-responseDone:
		if status != http.StatusOK {
			t.Fatalf("draining response=%d", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not finish")
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

type blockingSnapshotStore struct {
	api.Store
	entered chan context.Context
}

func (st *blockingSnapshotStore) Snapshot(ctx context.Context) (map[string]api.Record, error) {
	st.entered <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStopSignalCancelsInitialSnapshotBeforeListen(t *testing.T) {
	st := &blockingSnapshotStore{entered: make(chan context.Context, 1)}
	s, err := api.New(st, api.Config{DefaultTTL: time.Hour, MaxTTL: time.Hour},
		api.WithCache(rcu.Factory(time.Minute), 2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	signalCtx, stopSignal := context.WithCancel(context.Background())
	defer stopSignal()
	listened := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- startAndServe(signalCtx, s, func() error {
			listened <- struct{}{}
			return nil
		})
	}()
	select {
	case <-st.entered:
	case <-time.After(time.Second):
		t.Fatal("initial snapshot did not start")
	}
	stopSignal()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("startup error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("initial snapshot was not canceled promptly")
	}
	select {
	case <-listened:
		t.Fatal("HTTP listener was opened after stop signal")
	default:
	}
}

func TestServiceStaysLiveAfterSignalUntilServeReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := api.New(&blockingStore{}, api.Config{DefaultTTL: time.Hour, MaxTTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		signalCtx, stopSignal := context.WithCancel(context.Background())
		defer stopSignal()
		err = startAndServe(signalCtx, s, func() error {
			stopSignal()
			// Any AfterFunc mistakenly left attached to the signal has run.
			synctest.Wait()
			if _, err := s.Authenticate(context.Background(), "invalid"); !errors.Is(err, api.ErrUnauthorized) {
				t.Fatalf("service during drain: %v, want ErrUnauthorized", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := s.Authenticate(context.Background(), "invalid"); !errors.Is(err, api.ErrClosed) {
			t.Fatalf("service after drain: %v, want ErrClosed", err)
		}
	})
}

func TestOptionalFlagsValidateBeforeDatabaseSetup(t *testing.T) {
	t.Setenv("API_DATABASE_URL", "")
	t.Setenv("API_SCHEMA", "")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"usage administration", []string{"clients", "-usage"}, "-usage is only supported by serve"},
		{"audit missing actor", []string{"issue", "-audit"}, "-audit requires -actor"},
		{"invalid actor kind", []string{"issue", "-audit", "-actor", "operator", "-actor-kind", "business-token"}, "-audit requires -actor"},
		{"human actor", []string{"issue", "-audit", "-actor", "operator", "-actor-kind", "human"}, "API_DATABASE_URL and API_SCHEMA are required"},
		{"default service actor", []string{"issue", "-audit", "-actor", "operator"}, "API_DATABASE_URL and API_SCHEMA are required"},
		{"serve usage", []string{"serve", "-usage"}, "API_DATABASE_URL and API_SCHEMA are required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := run(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run error=%v want %q", err, tc.want)
			}
		})
	}
}

func TestNewManagementCommandsRequireIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		command string
		flags   flags
		want    string
	}{
		{"detail", flags{}, "-credential is required"},
		{"versions", flags{}, "-credential is required"},
		{"retire-version", flags{}, "-credential is required"},
		{"retire-version", flags{credential: "credential"}, "-version is required"},
		{"operation", flags{}, "-operation-id is required"},
	} {
		t.Run(tc.command+tc.want, func(t *testing.T) {
			if !knownCommand(tc.command) {
				t.Fatal("command not recognized")
			}
			if err := execute(context.Background(), tc.command, tc.flags, nil); err == nil || err.Error() != tc.want {
				t.Fatalf("error=%v want=%q", err, tc.want)
			}
		})
	}
	if !knownCommand("audit-events") {
		t.Fatal("audit-events not recognized")
	}
}

func TestManagementCLIIntegration(t *testing.T) {
	url := os.Getenv("API_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("API_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	schema := fmt.Sprintf("access_cli_%d", time.Now().UnixNano())
	defer func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := pool.Exec(cleanupCtx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	t.Setenv("API_DATABASE_URL", url)
	t.Setenv("API_SCHEMA", schema)

	command := func(target any, args ...string) error {
		t.Helper()
		file, err := os.CreateTemp(t.TempDir(), "cli-output")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		old := os.Stdout
		os.Stdout = file
		defer func() { os.Stdout = old }()
		if err := run(args); err != nil {
			return err
		}
		if target != nil {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if err := json.NewDecoder(file).Decode(target); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}
	must := func(target any, args ...string) {
		t.Helper()
		if err := command(target, args...); err != nil {
			t.Fatalf("%s failed: %v", args[0], err)
		}
	}
	must(nil, "migrate")
	var client api.Client
	must(&client, "create-client", "-name", "cli", "-scopes", "orders:read", "-audit", "-actor", "operator")
	issueArgs := []string{"issue", "-client", client.ID, "-name", "reader", "-scopes", "orders:read", "-operation-id", "cli-issue", "-audit", "-actor", "operator"}
	var issued, replay api.OperationResult
	must(&issued, issueArgs...)
	must(&replay, issueArgs...)
	if issued.Issued == nil || issued.Issued.Token == "" || replay.Issued != nil || replay.Receipt.ID != issued.Receipt.ID {
		t.Fatal("issue-once CLI did not preserve one-time token output")
	}
	id := issued.Receipt.Credential.ID
	var rotated api.OperationResult
	must(&rotated, "rotate", "-credential", id, "-generation", "1", "-grace", "1h", "-operation-id", "cli-rotate", "-audit", "-actor", "operator")
	if rotated.Issued == nil || rotated.Receipt.Version.Generation != 2 {
		t.Fatal("rotate-once CLI did not rotate")
	}
	var details api.CredentialDetails
	must(&details, "detail", "-credential", id)
	if details.Credential.Generation != 2 || details.UnexpiredVersions != 2 {
		t.Fatal("detail CLI returned inconsistent state")
	}
	var versions []api.SecretVersionInfo
	must(&versions, "versions", "-credential", id, "-limit", "1")
	if len(versions) != 1 || versions[0].Generation != 2 {
		t.Fatal("versions CLI did not paginate newest first")
	}
	must(&versions, "versions", "-credential", id, "-before-generation", "2", "-limit", "1")
	if len(versions) != 1 || versions[0].Generation != 1 {
		t.Fatal("versions CLI did not forward generation cursor")
	}
	if err := command(nil, "retire-version", "-credential", id, "-version", rotated.Receipt.Version.ID); !errors.Is(err, api.ErrConflict) {
		t.Fatalf("current retirement error=%v", err)
	}
	must(nil, "retire-version", "-credential", id, "-version", issued.Receipt.Version.ID, "-audit", "-actor", "operator")
	var receipt api.OperationReceipt
	must(&receipt, "operation", "-operation-id", "cli-rotate")
	if receipt.ID != rotated.Receipt.ID {
		t.Fatal("operation CLI returned wrong receipt")
	}
	var events []api.AuditEvent
	must(&events, "audit-events", "-limit", "1")
	if len(events) != 1 || events[0].Actor.ID != "operator" {
		t.Fatal("audit-events CLI returned wrong actor")
	}
	cursor := events[0].ID
	must(&events, "audit-events", "-before-event", fmt.Sprint(cursor), "-limit", "1")
	if len(events) != 1 || events[0].ID >= cursor {
		t.Fatal("audit-events CLI did not forward event cursor")
	}
}
