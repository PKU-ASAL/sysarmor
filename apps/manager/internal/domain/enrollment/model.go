package enrollment

import (
	"crypto/subtle"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type Status string

const (
	StatusActive Status = "active"
	StatusUsed   Status = "used"
	StatusIssued Status = "issued"
)

type Enrollment struct {
	ID                    string
	TenantID              tenant.ID
	AgentID               string
	HostID                string
	TokenHash             string
	TokenPreview          string
	BootstrapTokenHash    string
	BootstrapTokenPreview string
	BootstrapFetchedAt    time.Time
	GatewayAddress        string
	GatewayServerName     string
	Profile               string
	Labels                map[string]string
	CreatedBy             string
	Status                Status
	CreatedAt             time.Time
	ExpiresAt             time.Time
	UsedAt                time.Time
	IssuedAt              time.Time
	Issuance              Issuance
}

func (value Enrollment) RedeemBootstrap(bootstrapHash, tokenHash, tokenPreview string, at time.Time) (Enrollment, error) {
	bootstrapHash = strings.TrimSpace(bootstrapHash)
	tokenHash, tokenPreview = strings.TrimSpace(tokenHash), strings.TrimSpace(tokenPreview)
	if value.Status != StatusActive || !value.BootstrapFetchedAt.IsZero() ||
		!secureEqual(value.BootstrapTokenHash, bootstrapHash) {
		return Enrollment{}, failure.New(failure.Conflict, "bootstrap ticket is not active")
	}
	if at.IsZero() || tokenHash == "" || tokenPreview == "" {
		return Enrollment{}, failure.New(failure.InvalidArgument, "bootstrap redemption is incomplete")
	}
	if !value.ExpiresAt.IsZero() && at.After(value.ExpiresAt) {
		return Enrollment{}, failure.New(failure.FailedPrecondition, "enrollment token is expired")
	}
	value.TokenHash, value.TokenPreview = tokenHash, tokenPreview
	value.BootstrapTokenHash, value.BootstrapTokenPreview = "", ""
	value.BootstrapFetchedAt = at.UTC()
	return value, nil
}

func NewEnrollment(value Enrollment) (Enrollment, error) {
	value.ID = strings.TrimSpace(value.ID)
	value.TokenHash = strings.TrimSpace(value.TokenHash)
	if value.ID == "" || value.TenantID == "" || value.TokenHash == "" {
		return Enrollment{}, failure.New(failure.InvalidArgument, "enrollment identity is required")
	}
	if value.Status == "" {
		value.Status = StatusActive
	}
	value.AgentID = strings.TrimSpace(value.AgentID)
	value.Labels = cloneLabels(value.Labels)
	if value.Status != StatusActive && value.Status != StatusUsed && value.Status != StatusIssued {
		return Enrollment{}, failure.New(failure.InvalidArgument, "enrollment status is invalid")
	}
	return value, nil
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

type Certificate struct {
	TenantID             tenant.ID
	AgentID              string
	EnrollmentID         string
	SerialNumber         string
	UnenrollmentProtocol string
	Subject              string
	NotBefore            time.Time
	NotAfter             time.Time
	CreatedAt            time.Time
	CertificatePEM       string
}

type Issuance struct {
	KeySHA256   string
	Certificate Certificate
	CAPEM       string
}

func (value Enrollment) Issue(issuance Issuance, at time.Time) (Enrollment, Certificate, error) {
	if value.Status == StatusIssued {
		if value.Issuance.KeySHA256 == strings.TrimSpace(issuance.KeySHA256) {
			return value, value.Issuance.Certificate, nil
		}
		return Enrollment{}, Certificate{}, failure.New(failure.Conflict, "enrollment token is bound to another key")
	}
	if value.Status != StatusActive {
		return Enrollment{}, Certificate{}, failure.New(failure.Conflict, "enrollment token is not active")
	}
	if at.IsZero() || strings.TrimSpace(issuance.KeySHA256) == "" || strings.TrimSpace(issuance.Certificate.SerialNumber) == "" {
		return Enrollment{}, Certificate{}, failure.New(failure.InvalidArgument, "certificate issuance is incomplete")
	}
	if !value.ExpiresAt.IsZero() && at.After(value.ExpiresAt) {
		return Enrollment{}, Certificate{}, failure.New(failure.FailedPrecondition, "enrollment token is expired")
	}
	certificate := issuance.Certificate
	certificate.TenantID, certificate.AgentID, certificate.EnrollmentID = value.TenantID, value.AgentID, value.ID
	certificate.CreatedAt = at.UTC()
	issuance.Certificate = certificate
	value.Status, value.UsedAt, value.IssuedAt, value.Issuance = StatusIssued, at.UTC(), at.UTC(), issuance
	return value, certificate, nil
}

func (value Enrollment) Consume(at time.Time) (Enrollment, error) {
	if value.Status != StatusActive {
		return Enrollment{}, failure.New(failure.Conflict, "enrollment token is not active")
	}
	if at.IsZero() {
		return Enrollment{}, failure.New(failure.InvalidArgument, "consumption time is required")
	}
	if !value.ExpiresAt.IsZero() && at.After(value.ExpiresAt) {
		return Enrollment{}, failure.New(failure.FailedPrecondition, "enrollment token is expired")
	}
	value.Status = StatusUsed
	value.UsedAt = at.UTC()
	return value, nil
}

type UnenrollmentStatus string

const (
	UnenrollmentPending   UnenrollmentStatus = "revoked_endpoint_pending"
	UnenrollmentCompleted UnenrollmentStatus = "endpoint_completed"
)

type UnenrollmentIdentity struct {
	TenantID          tenant.ID
	AgentID           string
	EnrollmentID      string
	CertificateSerial string
}

type Unenrollment struct {
	Identity            UnenrollmentIdentity
	Receipt             string
	CompletionTokenHash string
	Status              UnenrollmentStatus
	RevokedAt           time.Time
	CompletedAt         time.Time
}

type UnenrollmentCompletion struct {
	Identity  UnenrollmentIdentity
	Receipt   string
	TokenHash string
}

func NewPendingUnenrollment(identity UnenrollmentIdentity, receipt, tokenHash string, revokedAt time.Time) (Unenrollment, error) {
	identity = normalizeIdentity(identity)
	receipt, tokenHash = strings.TrimSpace(receipt), strings.TrimSpace(tokenHash)
	if !identity.valid() || receipt == "" || tokenHash == "" || revokedAt.IsZero() {
		return Unenrollment{}, failure.New(failure.InvalidArgument, "unenrollment identity is incomplete")
	}
	return Unenrollment{Identity: identity, Receipt: receipt, CompletionTokenHash: tokenHash, Status: UnenrollmentPending, RevokedAt: revokedAt.UTC()}, nil
}

func (value Unenrollment) Complete(completion UnenrollmentCompletion, at time.Time) (Unenrollment, error) {
	completion.Identity = normalizeIdentity(completion.Identity)
	completion.Receipt = strings.TrimSpace(completion.Receipt)
	completion.TokenHash = strings.TrimSpace(completion.TokenHash)
	if value.Status == UnenrollmentCompleted && value.matches(completion) {
		return value, nil
	}
	if value.Status != UnenrollmentPending || !value.matches(completion) {
		return Unenrollment{}, failure.New(failure.Conflict, "unenrollment completion identity mismatch")
	}
	if at.IsZero() {
		return Unenrollment{}, failure.New(failure.InvalidArgument, "completion time is required")
	}
	value.Status = UnenrollmentCompleted
	value.CompletedAt = at.UTC()
	return value, nil
}

func (value Unenrollment) matches(completion UnenrollmentCompletion) bool {
	return value.Identity == completion.Identity && secureEqual(value.Receipt, completion.Receipt) &&
		secureEqual(value.CompletionTokenHash, completion.TokenHash)
}

func secureEqual(left, right string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(left)), []byte(strings.ToLower(right))) == 1
}

func normalizeIdentity(value UnenrollmentIdentity) UnenrollmentIdentity {
	value.AgentID = strings.TrimSpace(value.AgentID)
	value.EnrollmentID = strings.TrimSpace(value.EnrollmentID)
	value.CertificateSerial = strings.TrimSpace(value.CertificateSerial)
	return value
}

func (value UnenrollmentIdentity) valid() bool {
	return value.TenantID != "" && value.AgentID != "" && value.EnrollmentID != "" && value.CertificateSerial != ""
}
