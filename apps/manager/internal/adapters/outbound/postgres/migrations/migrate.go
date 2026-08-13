package migrations

import (
	"context"
	"database/sql"
	"fmt"
)

const migrationLockID = 786451001

type MigrationResult struct {
	Version int `json:"version"`
}

func ApplyMigrations(ctx context.Context, db *sql.DB) (MigrationResult, error) {
	if db == nil {
		return MigrationResult{}, fmt.Errorf("postgres migration db is nil")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("open postgres migration connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SELECT pg_advisory_lock(%d)", migrationLockID)); err != nil {
		return MigrationResult{}, fmt.Errorf("lock postgres schema migration: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), fmt.Sprintf("SELECT pg_advisory_unlock(%d)", migrationLockID))
	}()
	exists, err := schemaMigrationsExist(ctx, conn)
	if err != nil {
		return MigrationResult{}, err
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`); err != nil {
		return MigrationResult{}, fmt.Errorf("initialize postgres migrations: %w", err)
	}
	applied := map[int]bool{}
	if exists {
		applied, err = loadAppliedMigrations(ctx, conn)
		if err != nil {
			return MigrationResult{}, err
		}
	}
	for _, migration := range Ordered() {
		if applied[migration.Version] {
			continue
		}
		if err := applyMigration(ctx, conn, migration); err != nil {
			return MigrationResult{}, err
		}
	}
	return MigrationResult{Version: PostgresVersion}, nil
}

func schemaMigrationsExist(ctx context.Context, conn *sql.Conn) (bool, error) {
	var exists bool
	err := conn.QueryRowContext(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect postgres migration state: %w", err)
	}
	return exists, nil
}

func loadAppliedMigrations(ctx context.Context, conn *sql.Conn) (map[int]bool, error) {
	rows, err := conn.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("list postgres migrations: %w", err)
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan postgres migration: %w", err)
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, conn *sql.Conn, migration Migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin postgres migration v%d: %w", migration.Version, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		return fmt.Errorf("apply postgres migration v%d %s: %w", migration.Version, migration.Name, err)
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("INSERT INTO schema_migrations (version) VALUES (%d)", migration.Version)); err != nil {
		return fmt.Errorf("record postgres migration v%d: %w", migration.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit postgres migration v%d: %w", migration.Version, err)
	}
	return nil
}
