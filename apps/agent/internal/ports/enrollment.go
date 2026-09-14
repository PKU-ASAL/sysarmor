package ports

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
)

const CompletionPrepared = "prepared"

type Enrollment struct {
	State               management.State
	TenantID            string
	AgentID             string
	EnrollmentID        string
	CertificateSerial   string
	ManagerURL          string
	GatewayAddress      string
	TLSCAPath           string
	TLSCertPath         string
	TLSKeyPath          string
	TLSServerName       string
	UploadHistory       bool
	ManagedFromSequence uint64
	RevocationConfirmed bool
	RevokedAt           time.Time
	RevocationReceipt   string
}

type UnenrollmentCompletion struct {
	Token     string
	TokenHash string
	Status    string
}

type EnrollmentStats struct {
	OldestEventSequence uint64
	LatestEventSequence uint64
}

type EnrollmentIdentity struct {
	TenantID string
	AgentID  string
}

type EnrollmentPreparation interface {
	PreparedEnrollment() Enrollment
}

type EnrollmentStore interface {
	Enrollment(context.Context) (Enrollment, error)
	Stats(context.Context) (EnrollmentStats, error)
	SetEnrolling(context.Context, Enrollment) error
	PrepareUnenrollment(context.Context, string, string) (Enrollment, UnenrollmentCompletion, error)
	UnenrollmentCompletion(context.Context) (UnenrollmentCompletion, bool, error)
	RecordUnenrollmentError(context.Context, string) error
	ConfirmEnrollmentRevocation(context.Context, string, time.Time) error
	CompleteUnenrollment(context.Context, string) error
}

type EnrollmentRuntime interface {
	Identity() EnrollmentIdentity
	PrepareEnrollment(context.Context, string, string) (EnrollmentPreparation, error)
	RollbackEnrollment(EnrollmentPreparation, error) error
	FinalizeEnrollment(EnrollmentPreparation) error
	StopEnrollmentNetwork()
	ReconcileEnrollment(Enrollment) error
	WithPolicyAuthority(func() error) error
	RevokeEnrollment(context.Context, Enrollment, string) (string, time.Time, error)
	RestoreStandalonePolicy(context.Context, func(context.Context) error) error
	RemoveEnrollmentCredentials(Enrollment) error
	ReportUnenrollmentCompletion(context.Context) (bool, error)
}
