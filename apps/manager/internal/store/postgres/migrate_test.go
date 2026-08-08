package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func TestApplyMigrationsExecutesPostgresSchema(t *testing.T) {
	db := openFakeDB(t, nil)
	got, err := ApplyMigrations(context.Background(), db)
	if err != nil {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
	if got.Version != 3 {
		t.Fatalf("migration version = %d, want 3", got.Version)
	}
	query := FakeAllQueries()
	for _, want := range []string{
		"SELECT pg_advisory_lock",
		"CREATE TABLE IF NOT EXISTS agents",
		"CREATE TABLE IF NOT EXISTS response_audit",
		"INSERT INTO schema_migrations (version) VALUES (1)",
		"CREATE TABLE IF NOT EXISTS agent_unenrollments",
		"INSERT INTO schema_migrations (version) VALUES (2)",
		"CREATE TABLE IF NOT EXISTS telemetry_batches",
		"INSERT INTO schema_migrations (version) VALUES (3)",
		"SELECT pg_advisory_unlock",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("migration query missing %q: %s", want, query)
		}
	}
	if strings.Contains(query, "CREATE TABLE IF NOT EXISTS incidents") {
		t.Fatal("migration still creates incident report table")
	}
}

func TestApplyMigrationsRejectsNilDB(t *testing.T) {
	if _, err := ApplyMigrations(context.Background(), nil); err == nil {
		t.Fatal("ApplyMigrations(nil) error = nil")
	}
}

func TestApplyMigrationsWrapsExecError(t *testing.T) {
	db := openFakeDB(t, errors.New("boom"))
	if _, err := ApplyMigrations(context.Background(), db); err == nil || !strings.Contains(err.Error(), "postgres migration") {
		t.Fatalf("ApplyMigrations() error = %v", err)
	}
}

func openFakeDB(t *testing.T, execErr error) *sql.DB {
	t.Helper()
	FakeSetExecError(execErr)
	db, err := sql.Open(FakeDriverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
