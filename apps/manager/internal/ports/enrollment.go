package ports

import (
	"context"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type EnrollmentRepository interface {
	ByTokenHash(context.Context, string) (domainenrollment.Enrollment, error)
	ByBootstrapTokenHash(context.Context, string) (domainenrollment.Enrollment, error)
	List(context.Context, tenant.ID, domainenrollment.Status) ([]domainenrollment.Enrollment, error)
	RedeemBootstrap(context.Context, domainenrollment.Enrollment, domainenrollment.Enrollment) error
	Put(context.Context, domainenrollment.Enrollment) error
}

type CertificateRepository interface {
	Put(context.Context, domainenrollment.Certificate) error
}

type UnenrollmentRepository interface {
	Get(context.Context, tenant.ID, string) (domainenrollment.Unenrollment, error)
	List(context.Context, tenant.ID) ([]domainenrollment.Unenrollment, error)
	Put(context.Context, domainenrollment.Unenrollment) error
}

type EnrollmentTransaction interface {
	Enrollments() EnrollmentRepository
	Certificates() CertificateRepository
	Unenrollments() UnenrollmentRepository
}

type EnrollmentUnitOfWork interface {
	Execute(context.Context, func(context.Context, EnrollmentTransaction) error) error
}

type CertificateIssuer interface {
	Issue(context.Context, domainenrollment.Enrollment, []byte) (domainenrollment.Issuance, error)
}

type EnrollmentToken struct {
	Plaintext string
	Hash      string
	Preview   string
}

type EnrollmentTokenGenerator interface {
	New() (EnrollmentToken, error)
}
