package enrollment

import (
	"encoding/json"
	"fmt"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type enrollmentRecord struct {
	ID                string                    `json:"enrollment_id"`
	TenantID          string                    `json:"tenant_id"`
	AgentID           string                    `json:"agent_id,omitempty"`
	TokenHash         string                    `json:"token_hash,omitempty"`
	GatewayAddress    string                    `json:"gateway_addr,omitempty"`
	GatewayServerName string                    `json:"gateway_sni,omitempty"`
	Status            domainenrollment.Status   `json:"status"`
	CreatedAt         time.Time                 `json:"created_at"`
	ExpiresAt         time.Time                 `json:"expires_at,omitempty"`
	UsedAt            time.Time                 `json:"used_at,omitempty"`
	IssuedAt          time.Time                 `json:"issued_at,omitempty"`
	Issuance          domainenrollment.Issuance `json:"issuance,omitempty"`
}

type certificateRecord struct {
	TenantID             string    `json:"tenant_id"`
	AgentID              string    `json:"agent_id"`
	EnrollmentID         string    `json:"enrollment_id"`
	SerialNumber         string    `json:"serial_number"`
	UnenrollmentProtocol string    `json:"unenrollment_protocol,omitempty"`
	Subject              string    `json:"subject,omitempty"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	CreatedAt            time.Time `json:"created_at"`
	CertificatePEM       string    `json:"certificate_pem,omitempty"`
}

type unenrollmentRecord struct {
	TenantID            string                              `json:"tenant_id"`
	AgentID             string                              `json:"agent_id"`
	EnrollmentID        string                              `json:"enrollment_id"`
	CertificateSerial   string                              `json:"certificate_serial"`
	Receipt             string                              `json:"revocation_receipt"`
	CompletionTokenHash string                              `json:"completion_token_hash,omitempty"`
	Status              domainenrollment.UnenrollmentStatus `json:"status"`
	RevokedAt           time.Time                           `json:"revoked_at"`
	CompletedAt         time.Time                           `json:"endpoint_completed_at,omitempty"`
}

func encodeEnrollment(value domainenrollment.Enrollment) ([]byte, error) {
	record := enrollmentRecord{ID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		TokenHash: value.TokenHash, GatewayAddress: value.GatewayAddress, GatewayServerName: value.GatewayServerName,
		Status: value.Status, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt,
		UsedAt: value.UsedAt, IssuedAt: value.IssuedAt, Issuance: value.Issuance}
	return json.Marshal(record)
}

func decodeEnrollment(raw []byte) (domainenrollment.Enrollment, error) {
	var record enrollmentRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return domainenrollment.Enrollment{}, fmt.Errorf("decode enrollment record: %w", err)
	}
	tenantID, err := tenant.NewID(record.TenantID)
	if err != nil {
		return domainenrollment.Enrollment{}, err
	}
	return domainenrollment.NewEnrollment(domainenrollment.Enrollment{ID: record.ID, TenantID: tenantID,
		AgentID: record.AgentID, TokenHash: record.TokenHash, GatewayAddress: record.GatewayAddress,
		GatewayServerName: record.GatewayServerName, Status: record.Status, CreatedAt: record.CreatedAt,
		ExpiresAt: record.ExpiresAt, UsedAt: record.UsedAt, IssuedAt: record.IssuedAt, Issuance: record.Issuance})
}

func encodeCertificate(value domainenrollment.Certificate) ([]byte, error) {
	record := certificateRecord{TenantID: value.TenantID.String(), AgentID: value.AgentID, EnrollmentID: value.EnrollmentID,
		SerialNumber: value.SerialNumber, UnenrollmentProtocol: value.UnenrollmentProtocol, Subject: value.Subject,
		NotBefore: value.NotBefore, NotAfter: value.NotAfter, CreatedAt: value.CreatedAt, CertificatePEM: value.CertificatePEM}
	return json.Marshal(record)
}

func encodeUnenrollment(value domainenrollment.Unenrollment) ([]byte, error) {
	record := unenrollmentRecord{TenantID: value.Identity.TenantID.String(), AgentID: value.Identity.AgentID,
		EnrollmentID: value.Identity.EnrollmentID, CertificateSerial: value.Identity.CertificateSerial,
		Receipt: value.Receipt, CompletionTokenHash: value.CompletionTokenHash, Status: value.Status,
		RevokedAt: value.RevokedAt, CompletedAt: value.CompletedAt}
	return json.Marshal(record)
}

func decodeUnenrollment(raw []byte) (domainenrollment.Unenrollment, error) {
	var record unenrollmentRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return domainenrollment.Unenrollment{}, fmt.Errorf("decode unenrollment record: %w", err)
	}
	tenantID, err := tenant.NewID(record.TenantID)
	if err != nil {
		return domainenrollment.Unenrollment{}, err
	}
	value, err := domainenrollment.NewPendingUnenrollment(domainenrollment.UnenrollmentIdentity{TenantID: tenantID,
		AgentID: record.AgentID, EnrollmentID: record.EnrollmentID, CertificateSerial: record.CertificateSerial},
		record.Receipt, record.CompletionTokenHash, record.RevokedAt)
	if err != nil {
		return domainenrollment.Unenrollment{}, err
	}
	if record.Status == domainenrollment.UnenrollmentCompleted {
		return value.Complete(domainenrollment.UnenrollmentCompletion{Identity: value.Identity,
			Receipt: value.Receipt, TokenHash: value.CompletionTokenHash}, record.CompletedAt)
	}
	return value, nil
}
