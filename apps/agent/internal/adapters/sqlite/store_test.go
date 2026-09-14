package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenCreatesSecureBaselineAndStandaloneIdentity(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	store, err := Open(t.Context(), Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	assertMode(t, root, 0o700)
	assertMode(t, filepath.Join(root, "spool"), 0o700)
	assertMode(t, filepath.Join(root, "agent.db"), 0o600)

	identity, err := store.DeviceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if identity.DeviceID == "" || identity.HostID == "" || identity.CreatedAt.IsZero() {
		t.Fatalf("identity=%+v", identity)
	}
	if got := pragma(t, store, "journal_mode"); got != "wal" {
		t.Fatalf("journal_mode=%q", got)
	}
	if got := pragma(t, store, "foreign_keys"); got != "1" {
		t.Fatalf("foreign_keys=%q", got)
	}
	if got := schemaVersion(t, store); got != currentSchemaVersion {
		t.Fatalf("schema version=%d", got)
	}
	var state string
	if err := store.db.QueryRow("SELECT state FROM enrollment WHERE singleton = 1").Scan(&state); err != nil || state != "standalone" {
		t.Fatalf("enrollment state=%q error=%v", state, err)
	}
}

func TestDeviceIdentitySurvivesReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	first := openStore(t, root)
	want, err := first.DeviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := openStore(t, root)
	defer second.Close()
	got, err := second.DeviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != want.DeviceID || got.CreatedAt != want.CreatedAt {
		t.Fatalf("identity changed: got=%+v want=%+v", got, want)
	}
}

func TestOpenMigratesV3EnrollmentToCompletionSchema(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE schema_meta(version INTEGER PRIMARY KEY);
INSERT INTO schema_meta(version) VALUES (3);
CREATE TABLE enrollment (
  singleton INTEGER PRIMARY KEY, state TEXT NOT NULL, tenant_id TEXT, agent_id TEXT, enrollment_id TEXT,
  certificate_serial TEXT, gateway_address TEXT, tls_ca_path TEXT, tls_cert_path TEXT, tls_key_path TEXT,
  tls_server_name TEXT, upload_history INTEGER NOT NULL, managed_from_seq INTEGER, revocation_confirmed INTEGER NOT NULL,
  revoked_at_ns INTEGER, revocation_receipt TEXT, transition_phase TEXT, last_transition_error TEXT, updated_at_ns INTEGER NOT NULL
);
INSERT INTO enrollment VALUES (1,'managed','tenant-a','agent-a','enroll-a','42','gateway','/ca','/cert','/key','',0,1,0,NULL,NULL,'','',?);`, time.Now().UTC().UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store := openStore(t, root)
	defer store.Close()
	enrollment, err := store.Enrollment(t.Context())
	if err != nil || enrollment.State != StateManaged || enrollment.EnrollmentID != "enroll-a" || enrollment.ManagerURL != "" {
		t.Fatalf("enrollment=%+v err=%v", enrollment, err)
	}
	var protocol string
	if err := store.db.QueryRow(`SELECT unenrollment_protocol FROM enrollment WHERE singleton=1`).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if got := schemaVersion(t, store); got != currentSchemaVersion || protocol != "legacy_mtls" {
		t.Fatalf("schema version=%d protocol=%q, want %d/legacy_mtls", got, protocol, currentSchemaVersion)
	}
	if _, ok, err := store.UnenrollmentCompletion(t.Context()); err != nil || ok {
		t.Fatalf("completion ok=%t err=%v", ok, err)
	}
}

func TestOpenMigratesV4EnrollmentProtocolProvenance(t *testing.T) {
	for _, test := range []struct {
		name, managerURL, protocol string
	}{
		{name: "missing manager URL fails closed", protocol: UnenrollmentProtocolCompletionV1},
		{name: "completion", managerURL: "https://manager.example", protocol: UnenrollmentProtocolCompletionV1},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "agent")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`CREATE TABLE schema_meta(version INTEGER PRIMARY KEY);
INSERT INTO schema_meta(version) VALUES (4);
CREATE TABLE enrollment (
  singleton INTEGER PRIMARY KEY, state TEXT NOT NULL, tenant_id TEXT, agent_id TEXT, enrollment_id TEXT,
  certificate_serial TEXT, manager_url TEXT, gateway_address TEXT, tls_ca_path TEXT, tls_cert_path TEXT,
  tls_key_path TEXT, tls_server_name TEXT, upload_history INTEGER NOT NULL, managed_from_seq INTEGER,
  revocation_confirmed INTEGER NOT NULL, revoked_at_ns INTEGER, revocation_receipt TEXT,
  transition_phase TEXT, last_transition_error TEXT, updated_at_ns INTEGER NOT NULL
);
INSERT INTO enrollment(singleton,state,tenant_id,agent_id,enrollment_id,certificate_serial,manager_url,gateway_address,
tls_ca_path,tls_cert_path,tls_key_path,tls_server_name,upload_history,managed_from_seq,revocation_confirmed,updated_at_ns)
VALUES (1,'managed','tenant-a','agent-a','enroll-a','42',?,'gateway','/ca','/cert','/key','',0,1,0,?);`, test.managerURL, time.Now().UTC().UnixNano())
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store := openStore(t, root)
			defer store.Close()
			enrollment, err := store.Enrollment(t.Context())
			if err != nil || enrollment.UnenrollmentProtocol != test.protocol || schemaVersion(t, store) != currentSchemaVersion {
				t.Fatalf("enrollment=%+v err=%v", enrollment, err)
			}
		})
	}
}

func openStore(t *testing.T, root string) *Store {
	t.Helper()
	store, err := Open(t.Context(), Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func pragma(t *testing.T, store *Store, name string) string {
	t.Helper()
	var value string
	if err := store.db.QueryRow("PRAGMA " + name).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func schemaVersion(t *testing.T, store *Store) int {
	t.Helper()
	var version int
	if err := store.db.QueryRow("SELECT version FROM schema_meta").Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode=%o want=%o", path, got, want)
	}
}
