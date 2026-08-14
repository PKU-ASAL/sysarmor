package sqlite

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const (
	CompletionPrepared = "prepared"
	CompletionReady    = "ready"
)

type UnenrollmentCompletion struct {
	TenantID          string
	AgentID           string
	EnrollmentID      string
	CertificateSerial string
	ManagerURL        string
	RevocationReceipt string
	Token             string
	TokenHash         string
	Status            string
	AttemptCount      uint64
	LastError         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (s *Store) PrepareUnenrollment(ctx context.Context, token, tokenHash string) (Enrollment, error) {
	token, tokenHash = strings.TrimSpace(token), strings.TrimSpace(tokenHash)
	if token == "" || !validCompletionTokenHash(tokenHash) {
		return Enrollment{}, fmt.Errorf("unenrollment completion token is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin unenrollment preparation: %w", err)
	}
	defer tx.Rollback()
	state, identity, err := enrollmentCompletionIdentity(ctx, tx)
	if err != nil {
		return Enrollment{}, err
	}
	if state == StateUnenrolling {
		if err := validatePreparedCompletion(ctx, tx, identity.EnrollmentID, tokenHash); err != nil {
			return Enrollment{}, err
		}
	} else if state != StateManaged {
		return Enrollment{}, fmt.Errorf("unenrollment requires managed state")
	} else if err := insertPreparedCompletion(ctx, tx, identity, token, tokenHash); err != nil {
		return Enrollment{}, err
	}
	if state == StateManaged {
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment SET state='unenrolling', revocation_confirmed=0,
transition_phase='revocation_pending', last_transition_error='', updated_at_ns=? WHERE singleton=1 AND state='managed'`, time.Now().UTC().UnixNano()); err != nil {
			return Enrollment{}, fmt.Errorf("begin unenrollment: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit unenrollment preparation: %w", err)
	}
	return s.Enrollment(ctx)
}

func (s *Store) UnenrollmentCompletion(ctx context.Context) (UnenrollmentCompletion, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id, agent_id, enrollment_id, certificate_serial, manager_url,
COALESCE(revocation_receipt,''), completion_token, completion_token_hash, status, attempt_count,
COALESCE(last_error,''), created_at_ns, updated_at_ns FROM unenrollment_completion WHERE singleton=1`)
	completion, err := scanUnenrollmentCompletion(row)
	if err == sql.ErrNoRows {
		return UnenrollmentCompletion{}, false, nil
	}
	if err != nil {
		return UnenrollmentCompletion{}, false, fmt.Errorf("read unenrollment completion: %w", err)
	}
	return completion, true, nil
}

func (s *Store) RecordCompletionAttempt(ctx context.Context, message string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE unenrollment_completion SET attempt_count=attempt_count+1,
last_error=?, updated_at_ns=? WHERE singleton=1 AND status='ready'`, strings.TrimSpace(message), time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("record completion attempt: %w", err)
	}
	return requireChangedRow(result, "ready unenrollment completion does not exist")
}

func (s *Store) AcknowledgeUnenrollmentCompletion(ctx context.Context, enrollmentID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM unenrollment_completion
WHERE singleton=1 AND enrollment_id=? AND status='ready'`, strings.TrimSpace(enrollmentID))
	if err != nil {
		return fmt.Errorf("acknowledge unenrollment completion: %w", err)
	}
	return requireChangedRow(result, "matching ready unenrollment completion does not exist")
}

type completionIdentity struct {
	TenantID, AgentID, EnrollmentID, CertificateSerial, ManagerURL, Protocol string
}

func enrollmentCompletionIdentity(ctx context.Context, tx *sql.Tx) (EnrollmentState, completionIdentity, error) {
	var state EnrollmentState
	var identity completionIdentity
	err := tx.QueryRowContext(ctx, `SELECT state, COALESCE(tenant_id,''), COALESCE(agent_id,''),
COALESCE(enrollment_id,''), COALESCE(certificate_serial,''), COALESCE(manager_url,''), unenrollment_protocol FROM enrollment WHERE singleton=1`).
		Scan(&state, &identity.TenantID, &identity.AgentID, &identity.EnrollmentID, &identity.CertificateSerial, &identity.ManagerURL, &identity.Protocol)
	if err != nil {
		return "", completionIdentity{}, fmt.Errorf("read enrollment for completion: %w", err)
	}
	return state, identity, nil
}

func insertPreparedCompletion(ctx context.Context, tx *sql.Tx, identity completionIdentity, token, tokenHash string) error {
	if identity.Protocol != UnenrollmentProtocolCompletionV1 || strings.TrimSpace(identity.ManagerURL) == "" ||
		strings.TrimSpace(identity.EnrollmentID) == "" || strings.TrimSpace(identity.CertificateSerial) == "" {
		return fmt.Errorf("enrollment completion identity is incomplete")
	}
	now := time.Now().UTC().UnixNano()
	_, err := tx.ExecContext(ctx, `INSERT INTO unenrollment_completion(singleton, tenant_id, agent_id, enrollment_id,
certificate_serial, manager_url, completion_token, completion_token_hash, status, created_at_ns, updated_at_ns)
VALUES(1,?,?,?,?,?,?,?,'prepared',?,?)`, identity.TenantID, identity.AgentID, identity.EnrollmentID,
		identity.CertificateSerial, identity.ManagerURL, token, tokenHash, now, now)
	if err != nil {
		return fmt.Errorf("persist unenrollment completion: %w", err)
	}
	return nil
}

func validatePreparedCompletion(ctx context.Context, tx *sql.Tx, enrollmentID, tokenHash string) error {
	var existingEnrollmentID, existingHash, status string
	err := tx.QueryRowContext(ctx, `SELECT enrollment_id, completion_token_hash, status
FROM unenrollment_completion WHERE singleton=1`).Scan(&existingEnrollmentID, &existingHash, &status)
	if err != nil {
		return fmt.Errorf("read prepared unenrollment completion: %w", err)
	}
	if existingEnrollmentID != enrollmentID || existingHash != tokenHash || status != CompletionPrepared {
		return fmt.Errorf("unenrollment completion preparation conflicts with existing state")
	}
	return nil
}

type completionRow interface {
	Scan(...any) error
}

func scanUnenrollmentCompletion(row completionRow) (UnenrollmentCompletion, error) {
	var completion UnenrollmentCompletion
	var createdAt, updatedAt int64
	err := row.Scan(&completion.TenantID, &completion.AgentID, &completion.EnrollmentID, &completion.CertificateSerial,
		&completion.ManagerURL, &completion.RevocationReceipt, &completion.Token, &completion.TokenHash, &completion.Status,
		&completion.AttemptCount, &completion.LastError, &createdAt, &updatedAt)
	completion.CreatedAt = time.Unix(0, createdAt).UTC()
	completion.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return completion, err
}

func validCompletionTokenHash(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}

func requireChangedRow(result sql.Result, message string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("%s", message)
	}
	return nil
}
