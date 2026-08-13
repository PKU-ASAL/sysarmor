package control

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
)

type RevocationRepository struct {
	db *sql.DB
}

type certificateDocument struct {
	TenantID          string         `json:"tenant_id"`
	AgentID           string         `json:"agent_id"`
	EnrollmentID      string         `json:"enrollment_id"`
	Serial            string         `json:"serial_number"`
	Protocol          string         `json:"unenrollment_protocol,omitempty"`
	RevokedAt         time.Time      `json:"revoked_at,omitempty"`
	RevocationReceipt string         `json:"revocation_receipt,omitempty"`
	Raw               map[string]any `json:"-"`
}

type unenrollmentDocument struct {
	TenantID            string    `json:"tenant_id"`
	AgentID             string    `json:"agent_id"`
	EnrollmentID        string    `json:"enrollment_id"`
	CertificateSerial   string    `json:"certificate_serial"`
	RevocationReceipt   string    `json:"revocation_receipt"`
	CompletionTokenHash string    `json:"completion_token_hash,omitempty"`
	Status              string    `json:"status"`
	RevokedAt           time.Time `json:"revoked_at"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

func NewRevocationRepository(db *sql.DB) RevocationRepository {
	return RevocationRepository{db: db}
}

func (repository RevocationRepository) Certificate(ctx context.Context, tenantID, serial string) (domaingateway.Certificate, bool, error) {
	var raw []byte
	err := repository.db.QueryRowContext(ctx, `SELECT data FROM agent_certificates WHERE tenant_id=$1 AND serial_number=$2`, tenantID, serial).Scan(&raw)
	if err == sql.ErrNoRows {
		return domaingateway.Certificate{}, false, nil
	}
	if err != nil {
		return domaingateway.Certificate{}, false, fmt.Errorf("read certificate: %w", err)
	}
	document, err := decodeCertificate(raw)
	if err != nil {
		return domaingateway.Certificate{}, false, err
	}
	return certificateDomain(document), true, nil
}

func (repository RevocationRepository) Revoke(ctx context.Context, request domaingateway.RevokeEnrollment) (domaingateway.Revocation, error) {
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return domaingateway.Revocation{}, err
	}
	defer tx.Rollback()
	document, err := lockCertificate(ctx, tx, request)
	if err != nil {
		return domaingateway.Revocation{}, err
	}
	result, err := persistRevocation(ctx, tx, request, document)
	if err != nil {
		return domaingateway.Revocation{}, err
	}
	if err := tx.Commit(); err != nil {
		return domaingateway.Revocation{}, fmt.Errorf("commit certificate revocation: %w", err)
	}
	return result, nil
}

func lockCertificate(ctx context.Context, tx *sql.Tx, request domaingateway.RevokeEnrollment) (certificateDocument, error) {
	result, err := tx.ExecContext(ctx, `UPDATE agent_certificates SET data=data WHERE tenant_id=$1 AND serial_number=$2`, request.TenantID, request.CertificateSerial)
	if err != nil {
		return certificateDocument{}, fmt.Errorf("lock certificate: %w", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return certificateDocument{}, failure.New(failure.NotFound, "agent certificate not found")
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT data FROM agent_certificates WHERE tenant_id=$1 AND serial_number=$2`, request.TenantID, request.CertificateSerial).Scan(&raw); err != nil {
		return certificateDocument{}, fmt.Errorf("read locked certificate: %w", err)
	}
	document, err := decodeCertificate(raw)
	if err != nil {
		return certificateDocument{}, err
	}
	if document.TenantID != request.TenantID || document.AgentID != request.AgentID || document.EnrollmentID != request.EnrollmentID || document.Serial != request.CertificateSerial {
		return certificateDocument{}, failure.New(failure.PermissionDenied, "certificate enrollment identity mismatch")
	}
	return document, nil
}

func persistRevocation(ctx context.Context, tx *sql.Tx, request domaingateway.RevokeEnrollment, certificate certificateDocument) (domaingateway.Revocation, error) {
	if certificate.RevokedAt.IsZero() {
		certificate.RevokedAt = time.Now().UTC()
	}
	if certificate.RevocationReceipt == "" {
		certificate.RevocationReceipt = revocationReceipt(request)
	}
	if err := updateCertificate(ctx, tx, certificate); err != nil {
		return domaingateway.Revocation{}, err
	}
	record := newUnenrollment(request, certificate)
	if err := validateExistingUnenrollment(ctx, tx, record); err != nil {
		return domaingateway.Revocation{}, err
	}
	if err := upsertRevocation(ctx, tx, record); err != nil {
		return domaingateway.Revocation{}, err
	}
	return domaingateway.Revocation{ReceiptID: certificate.RevocationReceipt, RevokedAt: certificate.RevokedAt, CompletionRequired: request.CompletionTokenHash != ""}, nil
}

func newUnenrollment(request domaingateway.RevokeEnrollment, certificate certificateDocument) unenrollmentDocument {
	status := "unknown_legacy"
	if request.CompletionTokenHash != "" {
		status = "revoked_endpoint_pending"
	}
	return unenrollmentDocument{TenantID: request.TenantID, AgentID: request.AgentID, EnrollmentID: request.EnrollmentID,
		CertificateSerial: request.CertificateSerial, RevocationReceipt: certificate.RevocationReceipt,
		CompletionTokenHash: strings.ToLower(request.CompletionTokenHash), Status: status,
		RevokedAt: certificate.RevokedAt, CreatedAt: certificate.RevokedAt, UpdatedAt: certificate.RevokedAt}
}

func validateExistingUnenrollment(ctx context.Context, tx *sql.Tx, expected unenrollmentDocument) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT data FROM agent_unenrollments WHERE tenant_id=$1 AND enrollment_id=$2`, expected.TenantID, expected.EnrollmentID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing unenrollment: %w", err)
	}
	var actual unenrollmentDocument
	if err := json.Unmarshal(raw, &actual); err != nil {
		return fmt.Errorf("decode existing unenrollment: %w", err)
	}
	if actual.AgentID != expected.AgentID || actual.CertificateSerial != expected.CertificateSerial || actual.RevocationReceipt != expected.RevocationReceipt || !strings.EqualFold(actual.CompletionTokenHash, expected.CompletionTokenHash) {
		return failure.New(failure.PermissionDenied, "unenrollment binding mismatch")
	}
	return nil
}

func updateCertificate(ctx context.Context, tx *sql.Tx, document certificateDocument) error {
	document.Raw["revoked_at"] = document.RevokedAt
	document.Raw["revocation_receipt"] = document.RevocationReceipt
	raw, err := json.Marshal(document.Raw)
	if err != nil {
		return fmt.Errorf("encode revoked certificate: %w", err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE agent_certificates SET revoked_at=$3,data=$4 WHERE tenant_id=$1 AND serial_number=$2`, document.TenantID, document.Serial, document.RevokedAt, raw)
	if err != nil {
		return fmt.Errorf("update revoked certificate: %w", err)
	}
	return nil
}

func upsertRevocation(ctx context.Context, tx *sql.Tx, record unenrollmentDocument) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode unenrollment: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_unenrollments (tenant_id,enrollment_id,agent_id,certificate_serial,status,revoked_at,created_at,updated_at,data) VALUES ($1,$2,$3,$4,$5,$6,$6,$6,$7) ON CONFLICT (tenant_id,enrollment_id) DO NOTHING`, record.TenantID, record.EnrollmentID, record.AgentID, record.CertificateSerial, record.Status, record.RevokedAt, raw)
	if err != nil {
		return fmt.Errorf("persist unenrollment: %w", err)
	}
	return nil
}

func decodeCertificate(raw []byte) (certificateDocument, error) {
	var document certificateDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return certificateDocument{}, fmt.Errorf("decode certificate: %w", err)
	}
	if err := json.Unmarshal(raw, &document.Raw); err != nil {
		return certificateDocument{}, fmt.Errorf("decode certificate fields: %w", err)
	}
	return document, nil
}

func certificateDomain(document certificateDocument) domaingateway.Certificate {
	return domaingateway.Certificate{TenantID: document.TenantID, AgentID: document.AgentID, EnrollmentID: document.EnrollmentID, Serial: document.Serial, Protocol: document.Protocol}
}

func revocationReceipt(request domaingateway.RevokeEnrollment) string {
	sum := sha256.Sum256([]byte(request.TenantID + "\x00" + request.AgentID + "\x00" + request.EnrollmentID + "\x00" + request.CertificateSerial))
	return "revoke-" + hex.EncodeToString(sum[:16])
}
