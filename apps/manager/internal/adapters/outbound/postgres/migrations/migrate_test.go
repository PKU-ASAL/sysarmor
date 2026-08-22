package migrations

import (
	"context"
	"database/sql"
	"database/sql/driver"
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
	if got.Version != 10 {
		t.Fatalf("migration version = %d, want 10", got.Version)
	}
	query := FakeAllQueries()
	for _, want := range []string{
		"SELECT pg_advisory_lock",
		"CREATE TABLE IF NOT EXISTS agents",
		"CREATE TABLE IF NOT EXISTS response_audit",
		"INSERT INTO schema_migrations (version) VALUES (1)",
		"CREATE TABLE IF NOT EXISTS agent_unenrollments",
		"INSERT INTO schema_migrations (version) VALUES (2)",
		"CREATE TABLE IF NOT EXISTS control_audit",
		"INSERT INTO schema_migrations (version) VALUES (5)",
		"CREATE TABLE IF NOT EXISTS response_decisions",
		"INSERT INTO schema_migrations (version) VALUES (6)",
		"DELETE FROM policy_assignments",
		"INSERT INTO schema_migrations (version) VALUES (7)",
		"DROP TABLE IF EXISTS worker_signal_processing",
		"DROP TABLE IF EXISTS worker_candidate_rejections",
		"DROP TABLE IF EXISTS telemetry_batches",
		"INSERT INTO schema_migrations (version) VALUES (10)",
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

func TestApplyMigrationsUpgradesExistingV3Schema(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryResultSets([][][]driver.Value{
		{{true}},
		{{int64(1)}, {int64(2)}, {int64(3)}},
	})
	got, err := ApplyMigrations(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 10 {
		t.Fatalf("version=%d, want 10", got.Version)
	}
	queries := FakeAllQueries()
	if !strings.Contains(queries, "CREATE TABLE IF NOT EXISTS control_audit") ||
		!strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (5)") ||
		!strings.Contains(queries, "CREATE TABLE IF NOT EXISTS response_decisions") ||
		!strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (6)") ||
		!strings.Contains(queries, "DELETE FROM policy_assignments") ||
		!strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (7)") ||
		!strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (10)") {
		t.Fatalf("existing schema upgrade did not apply current migrations:\n%s", queries)
	}
	if strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (3)") {
		t.Fatalf("v3 migration was replayed:\n%s", queries)
	}
}

func TestApplyMigrationsUpgradesExistingV6SchemaWithPolicyResetOnly(t *testing.T) {
	db := openFakeDB(t, nil)
	FakeSetQueryResultSets([][][]driver.Value{
		{{true}},
		{{int64(1)}, {int64(2)}, {int64(3)}, {int64(4)}, {int64(5)}, {int64(6)}},
	})
	got, err := ApplyMigrations(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 10 {
		t.Fatalf("version=%d, want 10", got.Version)
	}
	queries := FakeAllQueries()
	if !strings.Contains(queries, "DELETE FROM policy_assignments") || !strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (7)") || !strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (10)") {
		t.Fatalf("existing schema upgrade did not apply current migrations:\n%s", queries)
	}
	if strings.Contains(queries, "INSERT INTO schema_migrations (version) VALUES (6)") {
		t.Fatalf("v6 migration was replayed:\n%s", queries)
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
