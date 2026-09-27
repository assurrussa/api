package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Watch uses a dedicated connection so no LISTEN state can leak into the pool.
// It returns only when ctx is canceled or the pool cannot provide configuration.
func (s *Store) Watch(ctx context.Context, invalidate func()) error {
	return s.WatchWithErrors(ctx, invalidate, nil)
}

// WatchWithErrors reports failed connection/subscription attempts while
// continuing to reconnect. The pool's connection hooks also apply to LISTEN.
func (s *Store) WatchWithErrors(ctx context.Context, invalidate func(), report func(error)) error {
	if invalidate == nil {
		return invalid("invalidate callback required")
	}
	config := s.pool.Config()
	backoff := 100 * time.Millisecond
	for ctx.Err() == nil {
		conn, subscribed, err := s.connectAndListen(ctx, config, invalidate)
		if subscribed {
			backoff = 100 * time.Millisecond
		}
		if conn != nil {
			// Close discards LISTEN state, including on cancellation or network failure.
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = conn.Close(closeCtx) //nolint:contextcheck // Detached background context for connection teardown.
			cancel()
		}
		if ctx.Err() != nil {
			return nil //nolint:nilerr // Watch cleanly returns nil on context cancellation.
		}
		if report != nil && err != nil {
			report(err)
		}
		backoff = s.waitBackoff(ctx, backoff)
	}
	return nil
}

func (s *Store) connectAndListen(ctx context.Context, config *pgxpool.Config, invalidate func()) (*pgx.Conn, bool, error) {
	connConfig := config.ConnConfig.Copy()
	var err error
	if config.BeforeConnect != nil {
		err = config.BeforeConnect(ctx, connConfig)
	}
	var conn *pgx.Conn
	var subscribed bool
	if err == nil {
		conn, err = pgx.ConnectConfig(ctx, connConfig)
	}
	if err == nil && config.AfterConnect != nil {
		err = config.AfterConnect(ctx, conn)
	}
	if err == nil {
		_, err = conn.Exec(ctx, `LISTEN `+pgx.Identifier{s.channel}.Sanitize())
		if err == nil {
			subscribed = true
			invalidate() // Subscription is committed by the implicit LISTEN transaction.
			for ctx.Err() == nil {
				_, err = conn.WaitForNotification(ctx)
				if err != nil {
					break
				}
				invalidate()
			}
		}
	}
	return conn, subscribed, err
}

func (s *Store) waitBackoff(ctx context.Context, backoff time.Duration) time.Duration {
	timer := time.NewTimer(backoff)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			<-timer.C
		}
		return backoff
	case <-timer.C:
	}
	if backoff < 5*time.Second {
		backoff *= 2
		if backoff > 5*time.Second {
			backoff = 5 * time.Second
		}
	}
	return backoff
}
