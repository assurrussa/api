//go:build e2e

package e2e_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/assurrussa/api"
	"github.com/jackc/pgx/v5"
)

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	for _, mode := range []string{"strict", "arc", "rcu"} {
		t.Run(mode, func(t *testing.T) {
			f := h.fixture(t)
			// Notification tests finish before either periodic RCU refresh or
			// cache expiry could conceal a broken cross-process subscription.
			servers := []*server{
				f.server(t, mode, time.Minute, 30*time.Second),
				f.server(t, mode, time.Minute, 30*time.Second),
			}
			check := func(t *testing.T, token string, status int) {
				t.Helper()
				for _, s := range servers {
					if mode == "strict" {
						s.expect(t, token, status)
					} else {
						s.eventually(t, token, status, propagationBudget)
					}
				}
			}

			t.Run("issue_and_http_boundary", func(t *testing.T) {
				client := f.client(t, "orders:read,orders:write")
				issued := f.issue(t, client, "orders:read", "1h")
				for _, s := range servers {
					principal := decode[api.Principal](t, s.expect(t, issued.Token, http.StatusOK))
					if principal.ClientID != client.ID || principal.CredentialID != issued.Credential.ID || !slices.Equal(principal.Scopes, []string{"orders:read"}) {
						t.Fatal("HTTP principal does not match the issued grant")
					}
				}
				s := servers[0]
				s.expect(t, "", http.StatusUnauthorized)
				s.expect(t, "malformed", http.StatusUnauthorized)
				wrongSecret := issued.Token[:38] + "A" + issued.Token[39:]
				if wrongSecret == issued.Token {
					wrongSecret = issued.Token[:38] + "B" + issued.Token[39:]
				}
				s.expect(t, wrongSecret, http.StatusUnauthorized)
				s.expect(t, "api1_"+strings.Repeat("0", 32)+issued.Token[37:], http.StatusUnauthorized)
				for _, mutate := range []func(*http.Request){
					func(r *http.Request) {
						r.Header.Add("Authorization", "Bearer "+issued.Token)
						r.Header.Add("Authorization", "Bearer "+issued.Token)
					},
					func(r *http.Request) { r.Header.Set("Authorization", "Bearer  "+issued.Token) },
					func(r *http.Request) {
						r.Header.Set("Authorization", "Bearer "+strings.Repeat(" ", (1<<20)-2048)+"invalid")
					},
					func(r *http.Request) {
						r.URL.RawQuery = url.Values{"token": {issued.Token}, "access_token": {issued.Token}}.Encode()
					},
					func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "access_token", Value: issued.Token}) },
					func(r *http.Request) {
						body := "access_token=" + issued.Token
						r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
						r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					},
				} {
					if status, _ := s.request(t, "", mutate); status != http.StatusUnauthorized {
						t.Fatalf("unsupported bearer transport returned %d", status)
					}
				}
			})

			t.Run("scopes_and_issue_policy", func(t *testing.T) {
				client := f.client(t, "orders:read,orders:write")
				reader := f.issue(t, client, "orders:read,orders:write", "1h")
				writer := f.issue(t, client, "orders:write", "1h")
				empty := f.issue(t, client, "", "1h")
				check(t, reader.Token, http.StatusOK)
				check(t, writer.Token, http.StatusForbidden)
				check(t, empty.Token, http.StatusForbidden)
				f.mustCLI(t, "scopes", "-client", client.ID, "-scopes", "orders:write")
				check(t, reader.Token, http.StatusForbidden)
				f.deniedCLI(t, "forbidden", "issue", "-client", client.ID, "-name", "denied", "-scopes", "orders:read")
				f.mustCLI(t, "scopes", "-client", client.ID, "-scopes", "orders:read,orders:write")
				check(t, reader.Token, http.StatusOK)
				f.deniedCLI(t, "invalid input", "issue", "-client", client.ID, "-name", "denied", "-scopes", "unknown")
				for _, ttl := range []string{"-1s", "744h"} {
					f.deniedCLI(t, "invalid input", "issue", "-client", client.ID, "-name", "denied", "-ttl", ttl)
				}
				if got := decode[[]api.Credential](t, f.mustCLI(t, "credentials", "-client", client.ID)); len(got) != 3 {
					t.Fatal("rejected issuance left a credential behind")
				}
			})

			t.Run("ban_unban_and_admin_rejection", func(t *testing.T) {
				client := f.client(t, "orders:read")
				issued := f.issue(t, client, "orders:read", "1h")
				check(t, issued.Token, http.StatusOK)
				f.mustCLI(t, "ban", "-client", client.ID)
				check(t, issued.Token, http.StatusUnauthorized)
				f.deniedCLI(t, "forbidden", "issue", "-client", client.ID, "-name", "denied")
				f.deniedCLI(t, "forbidden", "rotate", "-credential", issued.Credential.ID, "-generation", "1")
				f.mustCLI(t, "unban", "-client", client.ID)
				check(t, issued.Token, http.StatusOK)
			})

			t.Run("immediate_rotation_and_irrevocable_revoke", func(t *testing.T) {
				client := f.client(t, "orders:read")
				first := f.issue(t, client, "orders:read", "1h")
				check(t, first.Token, http.StatusOK)
				second := f.rotate(t, first, "0s")
				if second.Credential.ID != first.Credential.ID || second.Credential.Generation != 2 || second.Token == first.Token {
					t.Fatal("rotation did not preserve grant identity and replace the secret")
				}
				check(t, first.Token, http.StatusUnauthorized)
				check(t, second.Token, http.StatusOK)
				f.deniedCLI(t, "conflict", "rotate", "-credential", first.Credential.ID, "-generation", "1")
				check(t, second.Token, http.StatusOK)
				f.mustCLI(t, "revoke", "-credential", first.Credential.ID)
				check(t, first.Token, http.StatusUnauthorized)
				check(t, second.Token, http.StatusUnauthorized)
				f.deniedCLI(t, "conflict", "rotate", "-credential", first.Credential.ID, "-generation", "2")
				f.mustCLI(t, "ban", "-client", client.ID)
				f.mustCLI(t, "unban", "-client", client.ID)
				check(t, second.Token, http.StatusUnauthorized)
			})

			t.Run("overlap_and_original_expiry", func(t *testing.T) {
				client := f.client(t, "orders:read")
				first := f.issue(t, client, "orders:read", "1h")
				second := f.rotate(t, first, "1500ms")
				for _, s := range servers {
					s.expect(t, first.Token, http.StatusOK)
					s.expect(t, second.Token, http.StatusOK)
				}
				third := f.rotate(t, second, "0s")
				check(t, second.Token, http.StatusUnauthorized)
				check(t, third.Token, http.StatusOK)
				for _, s := range servers {
					s.eventually(t, first.Token, http.StatusUnauthorized, 3*time.Second)
				}
				short := f.issue(t, client, "orders:read", "1500ms")
				check(t, short.Token, http.StatusOK)
				long := f.rotate(t, short, "1h")
				check(t, long.Token, http.StatusOK)
				for _, s := range servers {
					s.eventually(t, short.Token, http.StatusUnauthorized, time.Until(short.ExpiresAt)+time.Second)
				}
			})

			t.Run("expiry_then_admin_renewal", func(t *testing.T) {
				client := f.client(t, "orders:read")
				short := f.issue(t, client, "orders:read", "1200ms")
				check(t, short.Token, http.StatusOK)
				for _, s := range servers {
					s.eventually(t, short.Token, http.StatusUnauthorized, 3*time.Second)
				}
				renewed := f.rotate(t, short, "0s")
				check(t, renewed.Token, http.StatusOK)
			})

			t.Run("revoke_all_includes_overlapping_versions", func(t *testing.T) {
				client := f.client(t, "orders:read")
				first := f.issue(t, client, "orders:read", "1h")
				second := f.issue(t, client, "orders:read", "1h")
				rotated := f.rotate(t, first, "1h")
				for _, issued := range []api.Issued{first, second, rotated} {
					check(t, issued.Token, http.StatusOK)
				}
				f.mustCLI(t, "revoke-all", "-client", client.ID)
				for _, issued := range []api.Issued{first, second, rotated} {
					check(t, issued.Token, http.StatusUnauthorized)
				}
				fresh := f.issue(t, client, "orders:read", "1h")
				check(t, fresh.Token, http.StatusOK)
			})

			t.Run("concurrent_rotation_has_one_winner", func(t *testing.T) {
				client := f.client(t, "orders:read")
				first := f.issue(t, client, "orders:read", "1h")
				check(t, first.Token, http.StatusOK)
				start, results := make(chan struct{}), make(chan cliResult, 2)
				for range 2 {
					go func() {
						<-start
						results <- f.cli("rotate", "-credential", first.Credential.ID, "-generation", "1", "-grace", "0s")
					}()
				}
				close(start)
				var winners []api.Issued
				conflicts := 0
				for range 2 {
					r := <-results
					if r.err == nil {
						winners = append(winners, f.issued(t, r.output))
					} else if r.rejected() && len(r.output) == 0 && strings.Contains(r.stderr, "api: conflict") {
						conflicts++
					} else {
						t.Fatal("unexpected concurrent rotation outcome (output withheld)")
					}
				}
				if len(winners) != 1 || conflicts != 1 || winners[0].Credential.Generation != 2 {
					t.Fatalf("rotation winners=%d conflicts=%d", len(winners), conflicts)
				}
				check(t, first.Token, http.StatusUnauthorized)
				check(t, winners[0].Token, http.StatusOK)
			})
		})
	}

	t.Run("metadata_and_project_isolation", func(t *testing.T) {
		f := h.fixture(t)
		firstClient, secondClient := f.client(t, "orders:read"), f.client(t, "orders:read")
		first := f.issue(t, firstClient, "orders:read", "1h")
		second := f.issue(t, firstClient, "orders:read", "1h")
		clientsRaw := f.mustCLI(t, "clients", "-limit", "1")
		page := decode[[]api.Client](t, clientsRaw)
		if len(page) != 1 {
			t.Fatal("client page limit was not applied")
		}
		next := decode[[]api.Client](t, f.mustCLI(t, "clients", "-limit", "1", "-after", page[0].ID))
		if len(next) != 1 || next[0].ID <= page[0].ID || (next[0].ID != firstClient.ID && next[0].ID != secondClient.ID) {
			t.Fatal("client keyset pagination lost or repeated a client")
		}
		grantsRaw := f.mustCLI(t, "credentials", "-client", firstClient.ID, "-limit", "1")
		grants := decode[[]api.Credential](t, grantsRaw)
		if len(grants) != 1 {
			t.Fatal("credential page limit was not applied")
		}
		nextGrants := decode[[]api.Credential](t, f.mustCLI(t, "credentials", "-client", firstClient.ID, "-limit", "1", "-after", grants[0].ID))
		if len(nextGrants) != 1 || nextGrants[0].ID <= grants[0].ID || (nextGrants[0].ID != first.Credential.ID && nextGrants[0].ID != second.Credential.ID) {
			t.Fatal("credential keyset pagination lost or repeated a grant")
		}
		for _, raw := range [][]byte{clientsRaw, grantsRaw} {
			f.noSecrets(t, string(raw))
			if bytes.Contains(raw, []byte(`"digest"`)) || bytes.Contains(raw, []byte(`"token"`)) {
				t.Fatal("metadata exposed verification material")
			}
		}
		other := h.fixture(t)
		other.server(t, "strict", time.Minute, 30*time.Second).expect(t, first.Token, http.StatusUnauthorized)
	})

	t.Run("lost_notifications_have_bounded_staleness", func(t *testing.T) {
		for _, mode := range []string{"arc", "rcu"} {
			t.Run(mode, func(t *testing.T) {
				f := h.fixture(t)
				client := f.client(t, "orders:read")
				issued := f.issue(t, client, "orders:read", "1h")
				s := f.server(t, mode, 2*time.Second, 500*time.Millisecond)
				s.expect(t, issued.Token, http.StatusOK)
				// Fault injection only: bypass Store's NOTIFY while preserving the
				// authoritative change. Production writers must use Store/Service.
				if _, err := h.pool.Exec(h.ctx, "UPDATE "+pgx.Identifier{f.schema, "clients"}.Sanitize()+" SET banned=true WHERE id=$1", client.ID); err != nil {
					t.Fatal("cannot inject lost invalidation")
				}
				s.eventually(t, issued.Token, http.StatusUnauthorized, 3*time.Second)
				s.expect(t, issued.Token, http.StatusUnauthorized)
			})
		}
	})

	t.Run("listener_reconnection", func(t *testing.T) {
		for _, mode := range []string{"arc", "rcu"} {
			t.Run(mode, func(t *testing.T) {
				f := h.fixture(t)
				client := f.client(t, "orders:read")
				issued := f.issue(t, client, "orders:read", "1h")
				s := f.server(t, mode, time.Minute, 30*time.Second)
				s.expect(t, issued.Token, http.StatusOK)
				var pid int32
				if err := h.pool.QueryRow(h.ctx, `SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND query LIKE 'LISTEN %' AND state='idle'`, s.app).Scan(&pid); err != nil {
					t.Fatal("dedicated listener not found")
				}
				var terminated bool
				if err := h.pool.QueryRow(h.ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=$1 AND application_name=$2 AND query LIKE 'LISTEN %'`, pid, s.app).Scan(&terminated); err != nil || !terminated {
					t.Fatal("cannot terminate this test's listener")
				}
				eventually(t, propagationBudget, func() bool {
					var connected bool
					err := h.pool.QueryRow(h.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND pid<>$2 AND query LIKE 'LISTEN %' AND state='idle')`, s.app, pid).Scan(&connected)
					return err == nil && connected
				})
				f.mustCLI(t, "revoke", "-credential", issued.Credential.ID)
				s.eventually(t, issued.Token, http.StatusUnauthorized, propagationBudget)
			})
		}
	})

	t.Run("database_outage_and_recovery", func(t *testing.T) {
		f := h.fixture(t)
		client := f.client(t, "orders:read")
		issued := f.issue(t, client, "orders:read", "1h")
		servers := make(map[string]*server)
		const maxAge = 2 * time.Second
		for _, mode := range []string{"strict", "arc", "rcu"} {
			servers[mode] = f.server(t, mode, maxAge, 500*time.Millisecond)
		}
		for _, s := range servers {
			s.expect(t, issued.Token, http.StatusOK)
		}
		h.docker(t, "stop", "--time", "2", h.container)
		stoppedAt := time.Now()
		servers["strict"].expect(t, issued.Token, http.StatusServiceUnavailable)
		for _, mode := range []string{"arc", "rcu"} {
			s := servers[mode]
			status, _ := s.request(t, issued.Token, nil)
			if status != http.StatusOK && status != http.StatusServiceUnavailable {
				t.Fatalf("%s returned %d during cache lease", mode, status)
			}
			t.Logf("%s during outage before freshness deadline: HTTP %d", mode, status)
		}
		// Check the mandatory post-expiry state even if a cold cache already
		// returned 503 earlier. Wait for this actual contract deadline, not a
		// guessed database readiness delay.
		select {
		case <-time.After(max(0, time.Until(stoppedAt.Add(maxAge+100*time.Millisecond)))):
		case <-h.ctx.Done():
			t.Fatal("test deadline exceeded while waiting for cache expiry")
		}
		for _, mode := range []string{"arc", "rcu"} {
			s := servers[mode]
			s.expect(t, issued.Token, http.StatusServiceUnavailable)
			s.expect(t, "api1_"+strings.Repeat("0", 32)+issued.Token[37:], http.StatusServiceUnavailable)
		}
		failed := f.cli("serve", "-cache", "rcu", "-addr", "127.0.0.1:0")
		if !failed.rejected() || len(failed.output) != 0 ||
			!strings.Contains(failed.stderr, "rcu: load snapshot:") || strings.Contains(failed.stderr, "listening on ") {
			t.Fatal("RCU startup did not report its initial snapshot failure before listening (output withheld)")
		}
		h.docker(t, "start", h.container)
		h.databaseReady(t)
		for mode, s := range servers {
			t.Run(fmt.Sprintf("%s_recovers", mode), func(t *testing.T) {
				s.eventually(t, issued.Token, http.StatusOK, 6*time.Second)
			})
		}
		f.mustCLI(t, "ban", "-client", client.ID)
		for _, s := range servers {
			s.eventually(t, issued.Token, http.StatusUnauthorized, propagationBudget)
		}
	})
}
