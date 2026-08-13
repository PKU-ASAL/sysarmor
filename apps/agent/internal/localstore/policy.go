package localstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type PolicyRecord struct {
	Kind      string
	Version   uint64
	Document  []byte
	Digest    string
	UpdatedAt time.Time
}

type PolicySource string

type PolicyStatus string

const (
	PolicySourceStandalone PolicySource = "standalone"
	PolicySourceManaged    PolicySource = "managed"
	PolicyStatusPending    PolicyStatus = "pending"
)

func (s *Store) PutDesiredManagedPolicy(ctx context.Context, policy PolicyRecord) error {
	if err := validatePolicyRecord(policy); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin desired policy update: %w", err)
	}
	defer tx.Rollback()
	if err := putDesiredPolicy(ctx, tx, PolicySourceManaged, policy); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DesiredPolicy(ctx context.Context, kind string, source PolicySource) (PolicyRecord, PolicyStatus, bool, error) {
	if err := validatePolicySource(source); err != nil {
		return PolicyRecord{}, "", false, err
	}
	var policy PolicyRecord
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT kind, version, document_json, digest, updated_at_ns FROM policy_desired WHERE kind=? AND source=?`, kind, source).Scan(
		&policy.Kind, &policy.Version, &policy.Document, &policy.Digest, &updatedAt)
	if err == sql.ErrNoRows {
		return PolicyRecord{}, "", false, nil
	}
	if err != nil {
		return PolicyRecord{}, "", false, err
	}
	policy.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if err := validatePolicyRecord(policy); err != nil {
		return PolicyRecord{}, "", false, err
	}
	return policy, PolicyStatusPending, true, nil
}

func (s *Store) PutAndActivateStandalonePolicy(ctx context.Context, policy PolicyRecord) error {
	return s.putAndActivatePolicy(ctx, PolicySourceStandalone, policy, false)
}

func (s *Store) InitializeStandalonePolicy(ctx context.Context, policy PolicyRecord) error {
	if err := validatePolicyRecord(policy); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin standalone policy initialization: %w", err)
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_slots WHERE kind=? AND source='standalone'`, policy.Kind).Scan(&exists); err != nil {
		return fmt.Errorf("read standalone policy slot: %w", err)
	}
	if exists > 0 {
		return nil
	}
	if err := putPolicySlot(ctx, tx, PolicySourceStandalone, policy); err != nil {
		return fmt.Errorf("initialize standalone policy slot: %w", err)
	}
	return tx.Commit()
}

func (s *Store) ActivateManagedPolicy(ctx context.Context, policy PolicyRecord) error {
	return s.putAndActivatePolicy(ctx, PolicySourceManaged, policy, true)
}

func (s *Store) ActivateStandalonePolicy(ctx context.Context, kind string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin standalone policy activation: %w", err)
	}
	defer tx.Rollback()
	var state EnrollmentState
	if err := tx.QueryRowContext(ctx, `SELECT state FROM enrollment WHERE singleton=1`).Scan(&state); err != nil {
		return fmt.Errorf("read enrollment for standalone policy: %w", err)
	}
	if state != StateStandalone {
		return fmt.Errorf("standalone policy activation requires standalone enrollment")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO policy_activation(kind, source, updated_at_ns)
SELECT kind, source, ? FROM policy_slots WHERE kind=? AND source='standalone'
ON CONFLICT(kind) DO UPDATE SET source=excluded.source, updated_at_ns=excluded.updated_at_ns`, time.Now().UTC().UnixNano(), kind)
	if err != nil {
		return fmt.Errorf("activate standalone policy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("standalone policy slot %q does not exist", kind)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_desired WHERE kind=?`, kind); err != nil {
		return fmt.Errorf("clear desired policies: %w", err)
	}
	return tx.Commit()
}

func (s *Store) putAndActivatePolicy(ctx context.Context, source PolicySource, policy PolicyRecord, promoteEnrollment bool) error {
	if err := validatePolicySource(source); err != nil {
		return err
	}
	if err := validatePolicyRecord(policy); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin active policy update: %w", err)
	}
	defer tx.Rollback()
	if promoteEnrollment {
		var state EnrollmentState
		if err := tx.QueryRowContext(ctx, `SELECT state FROM enrollment WHERE singleton=1`).Scan(&state); err != nil {
			return fmt.Errorf("read enrollment for managed policy: %w", err)
		}
		if state != StateEnrolling && state != StateManaged {
			return fmt.Errorf("managed policy activation requires enrolling or managed enrollment")
		}
	}
	if err := putPolicySlot(ctx, tx, source, policy); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_activation(kind, source, updated_at_ns) VALUES (?, ?, ?)
ON CONFLICT(kind) DO UPDATE SET source=excluded.source, updated_at_ns=excluded.updated_at_ns`, policy.Kind, source, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("activate policy: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_desired WHERE kind=? AND source=?`, policy.Kind, source); err != nil {
		return fmt.Errorf("clear desired policy: %w", err)
	}
	if promoteEnrollment {
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment SET state='managed', updated_at_ns=? WHERE singleton=1 AND state='enrolling'`, time.Now().UTC().UnixNano()); err != nil {
			return fmt.Errorf("promote managed enrollment: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit active policy update: %w", err)
	}
	return nil
}

func (s *Store) PolicySlot(ctx context.Context, kind string, source PolicySource) (PolicyRecord, bool, error) {
	if err := validatePolicySource(source); err != nil {
		return PolicyRecord{}, false, err
	}
	return scanPolicy(s.db.QueryRowContext(ctx, `SELECT kind, version, document_json, digest, updated_at_ns FROM policy_slots WHERE kind=? AND source=?`, kind, source))
}

func (s *Store) ActivePolicy(ctx context.Context, kind string) (PolicyRecord, PolicySource, bool, error) {
	var source PolicySource
	var policy PolicyRecord
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT p.kind, p.version, p.document_json, p.digest, p.updated_at_ns, a.source
FROM policy_activation a JOIN policy_slots p ON p.kind=a.kind AND p.source=a.source WHERE a.kind=?`, kind).Scan(
		&policy.Kind, &policy.Version, &policy.Document, &policy.Digest, &updatedAt, &source)
	if err == sql.ErrNoRows {
		return PolicyRecord{}, "", false, nil
	}
	if err != nil {
		return PolicyRecord{}, "", false, err
	}
	policy.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if err := validatePolicyRecord(policy); err != nil {
		return PolicyRecord{}, "", false, fmt.Errorf("read active policy: %w", err)
	}
	return policy, source, true, nil
}

func (s *Store) PutPolicy(ctx context.Context, policy PolicyRecord) error {
	if err := validatePolicyRecord(policy); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy update: %w", err)
	}
	defer tx.Rollback()
	var currentVersion uint64
	var currentDigest string
	var currentDocument []byte
	err = tx.QueryRowContext(ctx, `SELECT version, document_json, digest FROM policy WHERE kind = ?`, policy.Kind).Scan(&currentVersion, &currentDocument, &currentDigest)
	if err == nil {
		if policy.Version < currentVersion {
			return fmt.Errorf("policy version rollback: current=%d requested=%d", currentVersion, policy.Version)
		}
		if policy.Version == currentVersion && policy.Digest != currentDigest {
			return fmt.Errorf("policy digest conflict at version %d", policy.Version)
		}
		if policy.Version == currentVersion {
			if string(policy.Document) != string(currentDocument) {
				return fmt.Errorf("policy document conflict at version %d", policy.Version)
			}
			return nil
		}
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("read current policy: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy(kind, version, document_json, digest, updated_at_ns)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(kind) DO UPDATE SET version=excluded.version, document_json=excluded.document_json, digest=excluded.digest, updated_at_ns=excluded.updated_at_ns`,
		policy.Kind, policy.Version, policy.Document, policy.Digest, now.UnixNano()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy update: %w", err)
	}
	return nil
}

func (s *Store) Policy(ctx context.Context, kind string) (PolicyRecord, bool, error) {
	if policy, _, ok, err := s.ActivePolicy(ctx, kind); err != nil || ok {
		return policy, ok, err
	}
	var policy PolicyRecord
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT kind, version, document_json, digest, updated_at_ns FROM policy WHERE kind = ?`, kind).Scan(
		&policy.Kind, &policy.Version, &policy.Document, &policy.Digest, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return PolicyRecord{}, false, nil
	}
	if err != nil {
		return PolicyRecord{}, false, err
	}
	policy.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if digest := documentDigest(policy.Document); !strings.EqualFold(policy.Digest, digest) {
		return PolicyRecord{}, false, fmt.Errorf("stored policy %q digest mismatch", kind)
	}
	return policy, true, nil
}

func documentDigest(document []byte) string {
	digest := sha256.Sum256(document)
	return hex.EncodeToString(digest[:])
}

func validatePolicySource(source PolicySource) error {
	if source != PolicySourceStandalone && source != PolicySourceManaged {
		return fmt.Errorf("unsupported policy source %q", source)
	}
	return nil
}

func validatePolicyRecord(policy PolicyRecord) error {
	if strings.TrimSpace(policy.Kind) == "" || len(policy.Document) == 0 || strings.TrimSpace(policy.Digest) == "" {
		return fmt.Errorf("policy kind, document, and digest are required")
	}
	if digest := documentDigest(policy.Document); !strings.EqualFold(policy.Digest, digest) {
		return fmt.Errorf("policy digest mismatch: got=%s want=%s", policy.Digest, digest)
	}
	return nil
}

func putPolicySlot(ctx context.Context, tx *sql.Tx, source PolicySource, policy PolicyRecord) error {
	var currentVersion uint64
	var currentDigest string
	var currentDocument []byte
	err := tx.QueryRowContext(ctx, `SELECT version, document_json, digest FROM policy_slots WHERE kind=? AND source=?`, policy.Kind, source).Scan(&currentVersion, &currentDocument, &currentDigest)
	if err == nil {
		if err := validatePolicyTransition(policy, currentVersion, currentDocument, currentDigest); err != nil {
			return err
		}
		if policy.Version == currentVersion && policy.Digest == currentDigest && string(policy.Document) == string(currentDocument) {
			return nil
		}
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("read current policy slot: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO policy_slots(kind, source, version, document_json, digest, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, source) DO UPDATE SET version=excluded.version, document_json=excluded.document_json, digest=excluded.digest, updated_at_ns=excluded.updated_at_ns`,
		policy.Kind, source, policy.Version, policy.Document, policy.Digest, time.Now().UTC().UnixNano())
	return err
}

func putDesiredPolicy(ctx context.Context, tx *sql.Tx, source PolicySource, policy PolicyRecord) error {
	if err := validatePolicyAgainstSlot(ctx, tx, "policy_slots", source, policy); err != nil {
		return fmt.Errorf("validate desired policy against applied slot: %w", err)
	}
	if err := validatePolicyAgainstSlot(ctx, tx, "policy_desired", source, policy); err != nil {
		return fmt.Errorf("validate desired policy update: %w", err)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO policy_desired(kind, source, version, document_json, digest, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, source) DO UPDATE SET version=excluded.version, document_json=excluded.document_json, digest=excluded.digest, updated_at_ns=excluded.updated_at_ns`,
		policy.Kind, source, policy.Version, policy.Document, policy.Digest, time.Now().UTC().UnixNano())
	return err
}

func validatePolicyAgainstSlot(ctx context.Context, tx *sql.Tx, table string, source PolicySource, policy PolicyRecord) error {
	var currentVersion uint64
	var currentDigest string
	var currentDocument []byte
	query := fmt.Sprintf("SELECT version, document_json, digest FROM %s WHERE kind=? AND source=?", table)
	err := tx.QueryRowContext(ctx, query, policy.Kind, source).Scan(&currentVersion, &currentDocument, &currentDigest)
	if err == nil {
		return validatePolicyTransition(policy, currentVersion, currentDocument, currentDigest)
	}
	if err != sql.ErrNoRows {
		return err
	}
	return nil
}

func validatePolicyTransition(policy PolicyRecord, currentVersion uint64, currentDocument []byte, currentDigest string) error {
	currentID, nextID := policyDocumentID(currentDocument), policyDocumentID(policy.Document)
	if currentID != "" && nextID != "" && currentID != nextID {
		return nil
	}
	return validatePolicyUpdate(policy, currentVersion, currentDocument, currentDigest)
}

func policyDocumentID(document []byte) string {
	var value struct {
		PolicyID string `json:"policy_id"`
	}
	if json.Unmarshal(document, &value) != nil {
		return ""
	}
	return strings.TrimSpace(value.PolicyID)
}

func validatePolicyUpdate(policy PolicyRecord, currentVersion uint64, currentDocument []byte, currentDigest string) error {
	if policy.Version < currentVersion {
		return fmt.Errorf("policy version rollback: current=%d requested=%d", currentVersion, policy.Version)
	}
	if policy.Version == currentVersion && policy.Digest != currentDigest {
		return fmt.Errorf("policy digest conflict at version %d", policy.Version)
	}
	if policy.Version == currentVersion && string(policy.Document) != string(currentDocument) {
		return fmt.Errorf("policy document conflict at version %d", policy.Version)
	}
	return nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanPolicy(row rowScanner) (PolicyRecord, bool, error) {
	var policy PolicyRecord
	var updatedAt int64
	if err := row.Scan(&policy.Kind, &policy.Version, &policy.Document, &policy.Digest, &updatedAt); err == sql.ErrNoRows {
		return PolicyRecord{}, false, nil
	} else if err != nil {
		return PolicyRecord{}, false, err
	}
	policy.UpdatedAt = time.Unix(0, updatedAt).UTC()
	if err := validatePolicyRecord(policy); err != nil {
		return PolicyRecord{}, false, err
	}
	return policy, true, nil
}
