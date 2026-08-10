package ports

import (
	"context"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
)

type EnrollmentRepository interface {
	ByTokenHash(context.Context, string) (domainenrollment.Enrollment, error)
	Put(context.Context, domainenrollment.Enrollment) error
}

type CertificateRepository interface {
	Put(context.Context, domainenrollment.Certificate) error
}

type EnrollmentTransaction interface {
	Enrollments() EnrollmentRepository
	Certificates() CertificateRepository
}

type EnrollmentUnitOfWork interface {
	Execute(context.Context, func(context.Context, EnrollmentTransaction) error) error
}

type CertificateIssuer interface {
	Issue(context.Context, domainenrollment.Enrollment, []byte) (domainenrollment.Issuance, error)
}
