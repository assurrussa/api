package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/api"
	"github.com/assurrussa/api/cache/arc"
	"github.com/assurrussa/api/cache/rcu"
	"github.com/assurrussa/api/postgres"
)

const (
	benchScopeRead           = "read"
	benchTableSecretVersions = "secret_versions"
	benchModeArc             = "arc"
	benchModeRcu             = "rcu"
)

type countedStore struct {
	api.Store
	reads, scans atomic.Int64
}

func (s *countedStore) Lookup(ctx context.Context, id string) (api.Record, error) {
	s.reads.Add(1)
	return s.Store.Lookup(ctx, id)
}

func (s *countedStore) Snapshot(ctx context.Context) (map[string]api.Record, error) {
	s.scans.Add(1)
	return s.Store.Snapshot(ctx)
}

func seedBenchmark(b *testing.B, store *postgres.Store, pool *pgxpool.Pool, schema string, n int) []string {
	b.Helper()
	ctx := context.Background()
	at := time.Now().UTC()
	benchClient := api.Client{ID: "bench_client", Name: "benchmark", Scopes: []string{benchScopeRead}, CreatedAt: at}
	if err := store.CreateClient(ctx, benchClient); err != nil {
		b.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	credColumns := []string{"id", "client_id", "name", "scopes", "generation", "created_at"}
	_, err = tx.CopyFrom(ctx, pgx.Identifier{schema, "credentials"}, credColumns, pgx.CopyFromSlice(n, func(i int) ([]any, error) {
		return []any{fmt.Sprintf("%032x", i), "bench_client", benchScopeRead, []string{benchScopeRead}, int64(1), at}, nil
	}))
	if err != nil {
		b.Fatal(err)
	}
	tokens := make([]string, n)
	secColumns := []string{"id", "credential_id", "generation", "digest", "expires_at", "created_at"}
	_, err = tx.CopyFrom(
		ctx,
		pgx.Identifier{schema, benchTableSecretVersions},
		secColumns,
		pgx.CopyFromSlice(n, func(i int) ([]any, error) {
			id := fmt.Sprintf("%032x", i)
			raw := sha256.Sum256([]byte("public-benchmark-fixture-" + id))
			digest := sha256.Sum256(raw[:])
			tokens[i] = "api1_" + id + "." + base64.RawURLEncoding.EncodeToString(raw[:])
			return []any{id, id, int64(1), digest[:], at.Add(24 * time.Hour), at}, nil
		}),
	)
	if err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		b.Fatal(err)
	}
	return tokens
}

// BenchmarkPostgresVerification measures the complete verifier against a real
// primary, with a 128-key hot set. Mutations are one per 100 verifications.
// It is a scenario comparison, not a claimed throughput ceiling or SLO.
//
//nolint:gocognit // Benchmark matrix function with multiple runner permutations.
func BenchmarkPostgresVerification(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			store, pool, schema := database(b)
			tokens := seedBenchmark(b, store, pool, schema, n)
			for _, mode := range []string{"strict", benchModeArc, benchModeRcu} {
				for _, churn := range []bool{false, true} {
					b.Run(fmt.Sprintf("%s/churn=%t", mode, churn), func(b *testing.B) {
						counted := &countedStore{Store: store}
						var options []api.Option
						switch mode {
						case benchModeArc:
							options = append(options, api.WithCache(arc.Factory(1024), time.Hour))
						case benchModeRcu:
							options = append(options, api.WithCache(rcu.Factory(30*time.Minute), time.Hour))
						}
						runtime.GC()
						var before, after runtime.MemStats
						runtime.ReadMemStats(&before)
						s := newService(b, counted, options...)
						if err := s.Start(context.Background()); err != nil {
							b.Fatal(err)
						}
						for _, token := range tokens[:128] {
							requireAuth(b, s, token, nil, "read")
						}
						runtime.GC()
						runtime.ReadMemStats(&after)
						// Cumulative allocations are stable across benchmark calibration
						// rounds; heap deltas mix GC of previous rounds with this cache.
						initialAlloc := after.TotalAlloc - before.TotalAlloc
						startReads, startScans := counted.reads.Load(), counted.scans.Load()
						latencies := make([]int64, 0, 4096)
						stride := latencySampleStride(b.N)
						b.ReportAllocs()
						b.ResetTimer()
						for i := 0; i < b.N; i++ {
							if churn && i%100 == 0 {
								if err := s.SetClientBanned(context.Background(), "bench_client", false); err != nil {
									b.Fatal(err)
								}
							}
							var at time.Time
							if i%stride == 0 {
								at = time.Now()
							}
							if _, err := s.Authenticate(context.Background(), tokens[i%128], "read"); err != nil {
								b.Fatal(err)
							}
							if !at.IsZero() {
								latencies = append(latencies, time.Since(at).Nanoseconds())
							}
						}
						b.StopTimer()
						_ = s.Close()
						b.ReportMetric(float64(counted.reads.Load()-startReads)/float64(b.N), "db_reads/op")
						b.ReportMetric(float64(counted.scans.Load()-startScans)/float64(b.N), "db_scans/op")
						b.ReportMetric(float64(initialAlloc), "init-allocated-B")
						slices.Sort(latencies)
						b.ReportMetric(float64(latencies[len(latencies)/2]), "p50-ns")
						b.ReportMetric(float64(latencies[(len(latencies)-1)*95/100]), "p95-ns")
					})
				}
			}
		})
	}
}

// Avoid sampling the same phase of the 100-operation mutation cycle or the
// 128-token hot set throughout a run.
func latencySampleStride(operations int) int {
	stride := max(1, operations/4096)
	for stride%2 == 0 || stride%5 == 0 {
		stride++
	}
	return stride
}

func TestLatencySampleStride(t *testing.T) {
	for _, operations := range []int{1, 4096, 409600, 524288} {
		stride := latencySampleStride(operations)
		if stride < 1 || stride%2 == 0 || stride%5 == 0 {
			t.Fatalf("operations=%d: stride %d aliases the workload", operations, stride)
		}
	}
	stride := latencySampleStride(409600)
	mutations := 0
	var tokens [128]bool
	for i := 0; i < 409600; i += stride {
		if i%100 == 0 {
			mutations++
		}
		tokens[i%128] = true
	}
	if mutations == 0 {
		t.Fatal("samples never observe the mutation phase")
	}
	for token, seen := range tokens {
		if !seen {
			t.Fatalf("token %d is never sampled", token)
		}
	}
}

func BenchmarkPostgresSnapshot(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			store, pool, schema := database(b)
			_ = seedBenchmark(b, store, pool, schema, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snapshot, err := store.Snapshot(context.Background())
				if err != nil || len(snapshot) != n {
					b.Fatalf("snapshot size/error: %d %v", len(snapshot), err)
				}
			}
		})
	}
}
