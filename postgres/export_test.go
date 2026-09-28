package postgres

import (
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema returns the configured schema name for the store.
func (s *Store) Schema() string {
	return s.schema
}

// Pool returns the database connection pool.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// QuotedSchema returns the quoted schema identifier.
func (s *Store) QuotedSchema() string {
	return s.q
}

// Channel returns the notification channel name.
func (s *Store) Channel() string {
	return s.channel
}

// Table returns the qualified table name for the given table.
func (s *Store) Table(name string) string {
	return s.table(name)
}

// RollbackTimeout is the timeout duration used for rollbacks.
const RollbackTimeout = rollbackTimeout

// Rollback executes rollback on tx with a bounded timeout.
func Rollback(tx pgx.Tx) {
	rollback(tx)
}
