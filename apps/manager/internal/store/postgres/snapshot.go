package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/migrations"
)

const snapshotStateKey = "default"

// opTimeout bounds each backend database operation so a single query or
// projection cannot block indefinitely.
const opTimeout = 30 * time.Second

// sqlExecutor is satisfied by both *sql.DB and *sql.Tx, so projection and query
// helpers can run either directly or inside the state-projection transaction.
type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// tableBackend is the postgres implementation of store.Backend. It persists
// low-volume relational platform state only; high-volume telemetry (events and
// signals) is intentionally not projected here and lives in the index tier.
type tableBackend struct {
	db *sql.DB
}

func OpenTableStore(ctx context.Context, db *sql.DB, migration MigrationResult) (*store.Store, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres db is nil")
	}
	st, err := store.Open("")
	if err != nil {
		return nil, err
	}
	info := store.Info{
		Backend:          "postgres",
		StateVersion:     store.FileStoreStateVersion,
		MigrationVersion: migration.Version,
		PostgresSchema:   migrations.PostgresVersion,
	}
	st.AttachBackend(ctx, &tableBackend{db: db}, info)
	return st, nil
}

// withTimeout derives a bounded operation context from the store-supplied base
// context, so backend work is cancelled both on base-context cancellation
// (e.g. server shutdown) and after opTimeout.
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, opTimeout)
}

func (b *tableBackend) SaveState(ctx context.Context, state store.State) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return saveTables(ctx, b.db, state)
}

func (b *tableBackend) withTransaction(ctx context.Context, apply func(*sql.Tx) error) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// saveTables projects the full platform-state snapshot in a single transaction
// so a partially applied projection cannot leave the store inconsistent.
// Telemetry (events, signals) is deliberately excluded: it belongs in the index
// tier, not the relational state store.
func saveTables(ctx context.Context, db *sql.DB, state store.State) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin state projection tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := projectAgents(ctx, tx, state.Agents); err != nil {
		return err
	}
	if err := projectAgentHealth(ctx, tx, state.Health); err != nil {
		return err
	}
	if err := projectRules(ctx, tx, state.Rules); err != nil {
		return err
	}
	// Durable control-plane writers own responses and policy tables. Replaying
	// them from a process-local snapshot can overwrite newer cross-process state.
	if err := projectEnrollments(ctx, tx, state.Enrollments); err != nil {
		return err
	}
	if err := projectArtifacts(ctx, tx, state.Artifacts); err != nil {
		return err
	}
	if err := projectChannels(ctx, tx, state.Channels); err != nil {
		return err
	}
	if err := projectAgentCertificates(ctx, tx, state.Certificates); err != nil {
		return err
	}
	if err := projectEvidencePullbacks(ctx, tx, state.Pullbacks); err != nil {
		return err
	}
	if err := projectControlCommands(ctx, tx, state.ControlCommands); err != nil {
		return err
	}
	if err := projectAgentSessions(ctx, tx, state.AgentSessions); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state projection tx: %w", err)
	}
	committed = true
	return nil
}
