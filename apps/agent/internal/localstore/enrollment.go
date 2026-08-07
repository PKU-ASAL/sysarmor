package localstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/management"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
)

type EnrollmentState = management.State

const (
	StateStandalone  = management.StateStandalone
	StateEnrolling   = management.StateEnrolling
	StateManaged     = management.StateManaged
	StateUnenrolling = management.StateUnenrolling
)

const (
	UnenrollmentProtocolLegacyMTLS   = controlmodel.UnenrollmentProtocolLegacyMTLS
	UnenrollmentProtocolCompletionV1 = controlmodel.UnenrollmentProtocolCompletionV1
)

type Enrollment struct {
	State                EnrollmentState
	TenantID             string
	AgentID              string
	EnrollmentID         string
	CertificateSerial    string
	ManagerURL           string
	UnenrollmentProtocol string
	GatewayAddress       string
	TLSCAPath            string
	TLSCertPath          string
	TLSKeyPath           string
	TLSServerName        string
	UploadHistory        bool
	ManagedFromSequence  uint64
	RevocationConfirmed  bool
	RevokedAt            time.Time
	RevocationReceipt    string
	TransitionPhase      string
	LastTransitionError  string
	UpdatedAt            time.Time
}

func (s *Store) Enrollment(ctx context.Context) (Enrollment, error) {
	var enrollment Enrollment
	var uploadHistory int
	var revokedAt, updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT state, COALESCE(tenant_id,''), COALESCE(agent_id,''), COALESCE(gateway_address,''),
COALESCE(tls_ca_path,''), COALESCE(tls_cert_path,''), COALESCE(tls_key_path,''), COALESCE(tls_server_name,''), upload_history,
COALESCE(managed_from_seq,0), COALESCE(enrollment_id,''), COALESCE(certificate_serial,''), COALESCE(manager_url,''), unenrollment_protocol, revocation_confirmed,
COALESCE(revoked_at_ns,0), COALESCE(revocation_receipt,''), COALESCE(transition_phase,''), COALESCE(last_transition_error,''), updated_at_ns
FROM enrollment WHERE singleton = 1`).Scan(
		&enrollment.State, &enrollment.TenantID, &enrollment.AgentID, &enrollment.GatewayAddress,
		&enrollment.TLSCAPath, &enrollment.TLSCertPath, &enrollment.TLSKeyPath, &enrollment.TLSServerName,
		&uploadHistory, &enrollment.ManagedFromSequence, &enrollment.EnrollmentID, &enrollment.CertificateSerial, &enrollment.ManagerURL, &enrollment.UnenrollmentProtocol,
		&enrollment.RevocationConfirmed, &revokedAt, &enrollment.RevocationReceipt, &enrollment.TransitionPhase,
		&enrollment.LastTransitionError, &updatedAt,
	)
	enrollment.UploadHistory = uploadHistory != 0
	enrollment.RevokedAt = time.Unix(0, revokedAt).UTC()
	if revokedAt == 0 {
		enrollment.RevokedAt = time.Time{}
	}
	enrollment.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return enrollment, err
}

func (s *Store) SetEnrolling(ctx context.Context, enrollment Enrollment) error {
	if err := validateManaged(enrollment); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE enrollment SET state='enrolling', tenant_id=?, agent_id=?, enrollment_id=?, certificate_serial=?, manager_url=?, unenrollment_protocol='completion_v1', gateway_address=?, tls_ca_path=?,
tls_cert_path=?, tls_key_path=?, tls_server_name=?, upload_history=?, managed_from_seq=?, revocation_confirmed=0, revoked_at_ns=NULL,
revocation_receipt=NULL, transition_phase='', last_transition_error='', updated_at_ns=? WHERE singleton=1 AND state='standalone'
	AND NOT EXISTS (SELECT 1 FROM unenrollment_completion WHERE singleton=1)`,
		enrollment.TenantID, enrollment.AgentID, enrollment.EnrollmentID, enrollment.CertificateSerial, enrollment.ManagerURL, enrollment.GatewayAddress, enrollment.TLSCAPath, enrollment.TLSCertPath,
		enrollment.TLSKeyPath, enrollment.TLSServerName, enrollment.UploadHistory, enrollment.ManagedFromSequence, time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("enrollment requires standalone state with no pending manager completion")
	}
	return nil
}

func (s *Store) BeginUnenrollment(ctx context.Context) (Enrollment, error) {
	current, err := s.Enrollment(ctx)
	if err != nil {
		return Enrollment{}, err
	}
	if current.State == StateUnenrolling {
		return current, nil
	}
	if current.State != StateManaged {
		return Enrollment{}, fmt.Errorf("unenrollment requires managed state")
	}
	_, err = s.db.ExecContext(ctx, `UPDATE enrollment SET state='unenrolling', revocation_confirmed=0,
transition_phase='revocation_pending', last_transition_error='', updated_at_ns=? WHERE singleton=1 AND state='managed'`, time.Now().UTC().UnixNano())
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin unenrollment: %w", err)
	}
	return s.Enrollment(ctx)
}

func (s *Store) ConfirmEnrollmentRevocation(ctx context.Context, receipt string, revokedAt time.Time) error {
	if strings.TrimSpace(receipt) == "" || revokedAt.IsZero() {
		return fmt.Errorf("revocation confirmation is incomplete")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revocation confirmation: %w", err)
	}
	defer tx.Rollback()
	requiresCompletion, err := unenrollmentRequiresCompletion(ctx, tx)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE enrollment SET revocation_confirmed=1, revoked_at_ns=?, revocation_receipt=?,
transition_phase='revocation_confirmed', last_transition_error='', updated_at_ns=? WHERE singleton=1 AND state='unenrolling'`,
		revokedAt.UTC().UnixNano(), receipt, time.Now().UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("confirm enrollment revocation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		return fmt.Errorf("revocation confirmation requires unenrolling state")
	}
	if requiresCompletion {
		result, err = tx.ExecContext(ctx, `UPDATE unenrollment_completion SET revocation_receipt=?, updated_at_ns=?
WHERE singleton=1 AND status='prepared'`, receipt, time.Now().UTC().UnixNano())
		if err != nil {
			return fmt.Errorf("record completion revocation receipt: %w", err)
		}
		if err := requireChangedRow(result, "prepared unenrollment completion does not exist"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RecordUnenrollmentError(ctx context.Context, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enrollment SET last_transition_error=?, updated_at_ns=?
WHERE singleton=1 AND state='unenrolling'`, strings.TrimSpace(message), time.Now().UTC().UnixNano())
	return err
}

func (s *Store) CompleteUnenrollment(ctx context.Context, kind string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin unenrollment completion: %w", err)
	}
	defer tx.Rollback()
	var confirmed bool
	var protocol string
	if err := tx.QueryRowContext(ctx, `SELECT revocation_confirmed, unenrollment_protocol FROM enrollment
WHERE singleton=1 AND state='unenrolling'`).Scan(&confirmed, &protocol); err != nil || !confirmed {
		return fmt.Errorf("manager revocation confirmation is required")
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO policy_activation(kind, source, updated_at_ns)
SELECT kind, source, ? FROM policy_slots WHERE kind=? AND source='standalone'
ON CONFLICT(kind) DO UPDATE SET source=excluded.source, updated_at_ns=excluded.updated_at_ns`, time.Now().UTC().UnixNano(), kind)
	if err != nil {
		return fmt.Errorf("activate standalone policy: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows == 0 {
		return fmt.Errorf("standalone policy slot %q does not exist", kind)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_desired WHERE kind=?`, kind); err != nil {
		return fmt.Errorf("clear desired policies: %w", err)
	}
	switch protocol {
	case UnenrollmentProtocolCompletionV1:
		result, err = tx.ExecContext(ctx, `UPDATE unenrollment_completion SET status='ready',
revocation_receipt=(SELECT revocation_receipt FROM enrollment WHERE singleton=1), last_error='', updated_at_ns=?
		WHERE singleton=1 AND status='prepared'`, time.Now().UTC().UnixNano())
		if err != nil {
			return fmt.Errorf("mark unenrollment completion ready: %w", err)
		}
		if err := requireChangedRow(result, "prepared unenrollment completion does not exist"); err != nil {
			return err
		}
	case UnenrollmentProtocolLegacyMTLS:
	case "":
		return fmt.Errorf("unenrollment protocol is missing")
	default:
		return fmt.Errorf("unsupported unenrollment protocol %q", protocol)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment SET state='standalone', tenant_id=NULL, agent_id=NULL, enrollment_id=NULL,
certificate_serial=NULL, manager_url=NULL, gateway_address=NULL, tls_ca_path=NULL, tls_cert_path=NULL, tls_key_path=NULL, tls_server_name=NULL,
upload_history=0, managed_from_seq=NULL, revocation_confirmed=0, revoked_at_ns=NULL, revocation_receipt=NULL,
transition_phase='', last_transition_error='', unenrollment_protocol='completion_v1', updated_at_ns=? WHERE singleton=1`, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("clear managed enrollment: %w", err)
	}
	return tx.Commit()
}

func unenrollmentRequiresCompletion(ctx context.Context, tx *sql.Tx) (bool, error) {
	var protocol string
	if err := tx.QueryRowContext(ctx, `SELECT unenrollment_protocol FROM enrollment
WHERE singleton=1 AND state='unenrolling'`).Scan(&protocol); err != nil {
		return false, fmt.Errorf("read unenrollment protocol: %w", err)
	}
	switch protocol {
	case UnenrollmentProtocolCompletionV1:
		return true, nil
	case UnenrollmentProtocolLegacyMTLS:
		return false, nil
	default:
		return false, fmt.Errorf("unsupported unenrollment protocol %q", protocol)
	}
}

func validateManaged(enrollment Enrollment) error {
	values := []string{
		enrollment.TenantID,
		enrollment.AgentID,
		enrollment.EnrollmentID,
		enrollment.CertificateSerial,
		enrollment.ManagerURL,
		enrollment.GatewayAddress,
		enrollment.TLSCAPath,
		enrollment.TLSCertPath,
		enrollment.TLSKeyPath,
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("managed enrollment fields are incomplete")
		}
	}
	return nil
}
