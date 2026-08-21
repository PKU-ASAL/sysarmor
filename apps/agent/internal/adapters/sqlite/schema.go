package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"
)

const currentSchemaVersion = 5

const baselineSchema = `
CREATE TABLE IF NOT EXISTS schema_meta (
  version INTEGER PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS device_identity (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  device_id TEXT NOT NULL UNIQUE,
  host_id TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  state TEXT NOT NULL CHECK (state IN ('standalone', 'enrolling', 'managed', 'unenrolling')),
	  tenant_id TEXT,
	  agent_id TEXT,
  enrollment_id TEXT,
  certificate_serial TEXT,
  manager_url TEXT,
  unenrollment_protocol TEXT NOT NULL DEFAULT 'completion_v1' CHECK (unenrollment_protocol IN ('legacy_mtls', 'completion_v1')),
  gateway_address TEXT,
  tls_ca_path TEXT,
  tls_cert_path TEXT,
  tls_key_path TEXT,
  tls_server_name TEXT,
  upload_history INTEGER NOT NULL DEFAULT 0,
	  managed_from_seq INTEGER,
	  revocation_confirmed INTEGER NOT NULL DEFAULT 0,
	  revoked_at_ns INTEGER,
	  revocation_receipt TEXT,
	  transition_phase TEXT,
	  last_transition_error TEXT,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS unenrollment_completion (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  tenant_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  enrollment_id TEXT NOT NULL,
  certificate_serial TEXT NOT NULL,
  manager_url TEXT NOT NULL,
  revocation_receipt TEXT,
  completion_token TEXT NOT NULL,
  completion_token_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('prepared', 'ready')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at_ns INTEGER NOT NULL,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy (
  kind TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  document_json BLOB NOT NULL,
  digest TEXT NOT NULL,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_slots (
  kind TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('standalone', 'managed')),
  version INTEGER NOT NULL,
  document_json BLOB NOT NULL,
  digest TEXT NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY (kind, source)
);
CREATE TABLE IF NOT EXISTS policy_desired (
  kind TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('standalone', 'managed')),
  version INTEGER NOT NULL,
  document_json BLOB NOT NULL,
  digest TEXT NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY (kind, source)
);
CREATE TABLE IF NOT EXISTS policy_activation (
  kind TEXT PRIMARY KEY,
  source TEXT NOT NULL CHECK (source IN ('standalone', 'managed')),
  updated_at_ns INTEGER NOT NULL,
  FOREIGN KEY (kind, source) REFERENCES policy_slots(kind, source)
);
CREATE TABLE IF NOT EXISTS signals (
  sequence INTEGER PRIMARY KEY,
  signal_id TEXT NOT NULL UNIQUE,
  observed_at_ns INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  payload BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS signals_observed_at ON signals(observed_at_ns);
CREATE INDEX IF NOT EXISTS signals_rule_time ON signals(rule_id, observed_at_ns);
CREATE INDEX IF NOT EXISTS signals_severity_time ON signals(severity, observed_at_ns);
CREATE TABLE IF NOT EXISTS segments (
  segment_id INTEGER PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK (state IN ('open', 'sealed')),
  first_sequence INTEGER NOT NULL,
  last_sequence INTEGER NOT NULL,
  record_count INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  created_at_ns INTEGER NOT NULL,
  sealed_at_ns INTEGER
);
CREATE TABLE IF NOT EXISTS upload_checkpoint (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  segment_id INTEGER,
  record_offset INTEGER NOT NULL,
  last_batch_id TEXT,
  updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_counters (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  dropped_batches_storage INTEGER NOT NULL DEFAULT 0,
  dropped_events_storage INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sequence_cursor (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  event_sequence INTEGER NOT NULL DEFAULT 0,
  signal_sequence INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO sequence_cursor(singleton,event_sequence,signal_sequence) VALUES (1,0,0);`

func (s *Store) initialize(ctx context.Context, dbPath string) error {
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure local state: %w", err)
		}
	}
	if err := os.Chmod(dbPath, 0o600); err != nil {
		return fmt.Errorf("secure local state: %w", err)
	}
	if err := s.applyBaseline(ctx); err != nil {
		return err
	}
	return s.ensureIdentity(ctx)
}

func (s *Store) applyBaseline(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local schema: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, baselineSchema); err != nil {
		return fmt.Errorf("create local schema: %w", err)
	}
	var version int
	err = tx.QueryRowContext(ctx, "SELECT version FROM schema_meta LIMIT 1").Scan(&version)
	if err == sql.ErrNoRows {
		version = currentSchemaVersion
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_meta(version) VALUES (?)", version); err != nil {
			return fmt.Errorf("record local schema: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read local schema version: %w", err)
	}
	if version == 1 {
		if err := migratePolicySlots(tx); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if err := migrateEnrollmentRevocation(tx); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if err := migrateUnenrollmentCompletion(tx); err != nil {
			return err
		}
		if err := migrateUnenrollmentProtocol(tx, true); err != nil {
			return err
		}
		version = currentSchemaVersion
	}
	if version == 4 {
		if err := migrateUnenrollmentProtocol(tx, false); err != nil {
			return err
		}
		version = currentSchemaVersion
	}
	if version != currentSchemaVersion {
		return fmt.Errorf("unsupported local schema version %d", version)
	}
	return tx.Commit()
}

func migratePolicySlots(tx *sql.Tx) error {
	now := time.Now().UTC().UnixNano()
	if _, err := tx.Exec(`ALTER TABLE enrollment RENAME TO enrollment_v1;
CREATE TABLE enrollment (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  state TEXT NOT NULL CHECK (state IN ('standalone', 'enrolling', 'managed')),
  tenant_id TEXT, agent_id TEXT, gateway_address TEXT, tls_ca_path TEXT, tls_cert_path TEXT, tls_key_path TEXT,
  tls_server_name TEXT, upload_history INTEGER NOT NULL DEFAULT 0, managed_from_seq INTEGER, updated_at_ns INTEGER NOT NULL
);
INSERT INTO enrollment(singleton,state,tenant_id,agent_id,gateway_address,tls_ca_path,tls_cert_path,tls_key_path,tls_server_name,
upload_history,managed_from_seq,updated_at_ns)
SELECT singleton,state,tenant_id,agent_id,gateway_address,tls_ca_path,tls_cert_path,tls_key_path,tls_server_name,
upload_history,managed_from_seq,updated_at_ns FROM enrollment_v1;
DROP TABLE enrollment_v1;`); err != nil {
		return fmt.Errorf("migrate enrollment states: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO policy_slots(kind, source, version, document_json, digest, updated_at_ns)
	SELECT kind, 'standalone', version, document_json, digest, updated_at_ns FROM policy
	WHERE NOT EXISTS (SELECT 1 FROM enrollment WHERE singleton=1 AND state='managed')`); err != nil {
		return fmt.Errorf("migrate standalone policy slots: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO policy_slots(kind, source, version, document_json, digest, updated_at_ns)
SELECT p.kind, 'managed', p.version, p.document_json, p.digest, p.updated_at_ns FROM policy p
WHERE EXISTS (SELECT 1 FROM enrollment WHERE singleton=1 AND state='managed')`); err != nil {
		return fmt.Errorf("migrate managed policy slots: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO policy_activation(kind, source, updated_at_ns)
	SELECT kind, CASE WHEN EXISTS (SELECT 1 FROM enrollment WHERE singleton=1 AND state='managed') THEN 'managed' ELSE 'standalone' END, ? FROM policy`, now); err != nil {
		return fmt.Errorf("activate migrated standalone policies: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM schema_meta"); err != nil {
		return fmt.Errorf("replace local schema version: %w", err)
	}
	if _, err := tx.Exec("INSERT INTO schema_meta(version) VALUES (?)", 2); err != nil {
		return fmt.Errorf("record migrated schema version: %w", err)
	}
	return nil
}

func migrateEnrollmentRevocation(tx *sql.Tx) error {
	if _, err := tx.Exec(`ALTER TABLE enrollment RENAME TO enrollment_v2;
CREATE TABLE enrollment (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  state TEXT NOT NULL CHECK (state IN ('standalone', 'enrolling', 'managed', 'unenrolling')),
  tenant_id TEXT, agent_id TEXT, enrollment_id TEXT, certificate_serial TEXT, gateway_address TEXT,
  tls_ca_path TEXT, tls_cert_path TEXT, tls_key_path TEXT, tls_server_name TEXT,
  upload_history INTEGER NOT NULL DEFAULT 0, managed_from_seq INTEGER,
  revocation_confirmed INTEGER NOT NULL DEFAULT 0, revoked_at_ns INTEGER, revocation_receipt TEXT,
  transition_phase TEXT, last_transition_error TEXT, updated_at_ns INTEGER NOT NULL
);
INSERT INTO enrollment(singleton,state,tenant_id,agent_id,gateway_address,tls_ca_path,tls_cert_path,tls_key_path,tls_server_name,
upload_history,managed_from_seq,updated_at_ns)
SELECT singleton,state,tenant_id,agent_id,gateway_address,tls_ca_path,tls_cert_path,tls_key_path,tls_server_name,
upload_history,managed_from_seq,updated_at_ns FROM enrollment_v2;
DROP TABLE enrollment_v2;
DELETE FROM schema_meta;
INSERT INTO schema_meta(version) VALUES (3);`); err != nil {
		return fmt.Errorf("migrate enrollment revocation state: %w", err)
	}
	return nil
}

func migrateUnenrollmentCompletion(tx *sql.Tx) error {
	if _, err := tx.Exec(`ALTER TABLE enrollment ADD COLUMN manager_url TEXT;
CREATE TABLE IF NOT EXISTS unenrollment_completion (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL, enrollment_id TEXT NOT NULL, certificate_serial TEXT NOT NULL,
  manager_url TEXT NOT NULL, revocation_receipt TEXT, completion_token TEXT NOT NULL, completion_token_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('prepared', 'ready')), attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT, created_at_ns INTEGER NOT NULL, updated_at_ns INTEGER NOT NULL
);
DELETE FROM schema_meta;
INSERT INTO schema_meta(version) VALUES (4);`); err != nil {
		return fmt.Errorf("migrate unenrollment completion state: %w", err)
	}
	return nil
}

func migrateUnenrollmentProtocol(tx *sql.Tx, legacy bool) error {
	if _, err := tx.Exec(`ALTER TABLE enrollment ADD COLUMN unenrollment_protocol TEXT NOT NULL DEFAULT 'completion_v1'
CHECK (unenrollment_protocol IN ('legacy_mtls', 'completion_v1'));`); err != nil {
		return fmt.Errorf("add unenrollment protocol: %w", err)
	}
	if legacy {
		if _, err := tx.Exec(`UPDATE enrollment SET unenrollment_protocol='legacy_mtls' WHERE state!='standalone'`); err != nil {
			return fmt.Errorf("mark migrated legacy unenrollment protocol: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM schema_meta;
INSERT INTO schema_meta(version) VALUES (5);`); err != nil {
		return fmt.Errorf("record unenrollment protocol migration: %w", err)
	}
	return nil
}
