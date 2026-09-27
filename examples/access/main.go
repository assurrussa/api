// Command access demonstrates project-local M2M credential administration and
// a single protected HTTP endpoint. It is deliberately an example, not a host
// configuration or administrative HTTP API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	api "github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/assurrussa/api/httpapi"
	"github.com/assurrussa/api/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type flags struct {
	client, credential, name, scopes, after string
	cache, addr                             string
	ttl, grace, maxStaleness, refresh       time.Duration
	snapshotTimeout                         time.Duration
	generation                              int64
	capacity, limit                         int
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: access <migrate|create-client|clients|issue|credentials|rotate|revoke|revoke-all|ban|unban|scopes|serve> [flags]")
	}
	command := args[0]
	if !knownCommand(command) {
		return fmt.Errorf("unknown command")
	}
	var f flags
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&f.client, "client", "", "client ID")
	fs.StringVar(&f.credential, "credential", "", "credential ID")
	fs.StringVar(&f.name, "name", "", "client or credential name")
	fs.StringVar(&f.scopes, "scopes", "", "comma-separated scopes")
	fs.StringVar(&f.after, "after", "", "pagination cursor ID")
	fs.IntVar(&f.limit, "limit", 100, "page size (1..1000)")
	fs.DurationVar(&f.ttl, "ttl", 0, "secret lifetime (zero uses example default)")
	fs.Int64Var(&f.generation, "generation", 0, "expected generation for rotation")
	fs.DurationVar(&f.grace, "grace", 0, "old-secret overlap during rotation")
	fs.StringVar(&f.cache, "cache", "strict", "strict, arc, or rcu")
	fs.DurationVar(&f.maxStaleness, "max-staleness", 30*time.Second, "maximum cache age")
	fs.DurationVar(&f.refresh, "refresh", 5*time.Second, "RCU refresh interval")
	fs.DurationVar(&f.snapshotTimeout, "snapshot-timeout", 0, "RCU snapshot timeout (zero uses refresh interval)")
	fs.IntVar(&f.capacity, "capacity", 10000, "ARC entry capacity")
	fs.StringVar(&f.addr, "addr", "127.0.0.1:8080", "HTTP listen address")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	url, schema := os.Getenv("API_DATABASE_URL"), os.Getenv("API_SCHEMA")
	if url == "" || schema == "" {
		return fmt.Errorf("API_DATABASE_URL and API_SCHEMA are required")
	}
	// Parse errors can include the input DSN. Do not print them.
	poolConfig, err := pgxpool.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("invalid API_DATABASE_URL")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return fmt.Errorf("cannot initialize database pool")
	}
	defer pool.Close()
	store, err := postgres.New(pool, schema)
	if err != nil {
		return err
	}
	if command == "migrate" {
		if err := store.Migrate(ctx); err != nil {
			return err
		}
		return output(map[string]any{"migrated": true, "schema": schema})
	}

	// Example-only policy. Real hosts own their scope catalog and TTL limits.
	cfg := api.Config{Scopes: []string{"orders:read", "orders:write"}, DefaultTTL: 24 * time.Hour, MaxTTL: 30 * 24 * time.Hour}
	var options []api.Option
	switch f.cache {
	case "strict":
	case "arc":
		options = append(options, api.WithCache(arc.Factory(f.capacity), f.maxStaleness))
	case "rcu":
		loadBudget := f.snapshotTimeout
		if loadBudget == 0 {
			loadBudget = f.refresh
		}
		options = append(options, api.WithCache(rcu.FactoryWithTimeout(f.refresh, loadBudget), f.maxStaleness))
	default:
		return fmt.Errorf("invalid -cache: choose strict, arc, or rcu")
	}
	service, err := api.New(store, cfg, options...)
	if err != nil {
		return err
	}
	defer service.Close()
	if command == "serve" {
		return startAndServe(ctx, service, func() error { return execute(ctx, command, f, service) })
	}
	if err := service.Start(ctx); err != nil {
		return err
	}
	return execute(ctx, command, f, service)
}

// startAndServe cancels the initial cache load on a stop signal. Once startup
// succeeds, the service stays live until the HTTP server has drained.
func startAndServe(signalCtx context.Context, service *api.Service, serve func() error) error {
	serviceCtx, cancelService := context.WithCancel(context.Background())
	defer cancelService()
	stopStartupCancel := context.AfterFunc(signalCtx, cancelService)
	err := service.Start(serviceCtx)
	stopStartupCancel()
	if signalErr := signalCtx.Err(); signalErr != nil {
		return signalErr
	}
	if err != nil {
		return err
	}
	return serve()
}

func knownCommand(command string) bool {
	switch command {
	case "migrate", "create-client", "clients", "issue", "credentials", "rotate", "revoke", "revoke-all", "ban", "unban", "scopes", "serve":
		return true
	default:
		return false
	}
}

func splitScopes(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func required(label, value string) error {
	if value == "" {
		return fmt.Errorf("-%s is required", label)
	}
	return nil
}

func execute(ctx context.Context, command string, f flags, s *api.Service) error {
	switch command {
	case "create-client":
		if err := required("name", f.name); err != nil {
			return err
		}
		v, err := s.CreateClient(ctx, f.name, splitScopes(f.scopes))
		if err != nil {
			return err
		}
		return output(v)
	case "clients":
		v, err := s.Clients(ctx, f.after, f.limit)
		if err != nil {
			return err
		}
		return output(v)
	case "issue":
		if err := required("client", f.client); err != nil {
			return err
		}
		if err := required("name", f.name); err != nil {
			return err
		}
		v, err := s.Issue(ctx, api.IssueRequest{ClientID: f.client, Name: f.name, Scopes: splitScopes(f.scopes), TTL: f.ttl})
		if err != nil {
			return err
		}
		return output(v)
	case "credentials":
		if err := required("client", f.client); err != nil {
			return err
		}
		v, err := s.Credentials(ctx, f.client, f.after, f.limit)
		if err != nil {
			return err
		}
		return output(v)
	case "rotate":
		if err := required("credential", f.credential); err != nil {
			return err
		}
		if f.generation <= 0 {
			return fmt.Errorf("-generation must be positive")
		}
		v, err := s.Rotate(ctx, api.RotateRequest{CredentialID: f.credential, ExpectedGeneration: f.generation, TTL: f.ttl, GracePeriod: f.grace})
		if err != nil {
			return err
		}
		return output(v)
	case "revoke":
		if err := required("credential", f.credential); err != nil {
			return err
		}
		if err := s.Revoke(ctx, f.credential); err != nil {
			return err
		}
		return output(map[string]bool{"revoked": true})
	case "revoke-all":
		if err := required("client", f.client); err != nil {
			return err
		}
		if err := s.RevokeAll(ctx, f.client); err != nil {
			return err
		}
		return output(map[string]bool{"revoked_all": true})
	case "ban", "unban":
		if err := required("client", f.client); err != nil {
			return err
		}
		banned := command == "ban"
		if err := s.SetClientBanned(ctx, f.client, banned); err != nil {
			return err
		}
		return output(map[string]bool{"banned": banned})
	case "scopes":
		if err := required("client", f.client); err != nil {
			return err
		}
		scopes := splitScopes(f.scopes)
		if err := s.SetClientScopes(ctx, f.client, scopes); err != nil {
			return err
		}
		return output(map[string]any{"scopes": scopes})
	case "serve":
		return serve(ctx, f.addr, s)
	}
	return errors.New("unreachable command")
}

func output(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }

func serve(ctx context.Context, addr string, s *api.Service) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return serveListener(ctx, listener, s)
}

func serveListener(ctx context.Context, listener net.Listener, s *api.Service) error {
	mux := http.NewServeMux()
	mux.Handle("GET /orders", ordersHandler(s, 5*time.Second))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer listener.Close()
	fmt.Fprintf(os.Stderr, "listening on http://%s\n", listener.Addr())
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	select {
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-served
			return err
		}
		err := <-served
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func ordersHandler(auth httpapi.Authenticator, authTimeout time.Duration) http.Handler {
	protected := httpapi.Middleware(auth, "orders:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := httpapi.Principal(r.Context())
		if !ok {
			http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(principal)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCtx, cancel := context.WithTimeout(r.Context(), authTimeout)
		defer cancel()
		protected.ServeHTTP(w, r.WithContext(requestCtx))
	})
}
