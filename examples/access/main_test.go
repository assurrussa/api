package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/rcu"
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
