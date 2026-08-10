package enrollment

import (
	"context"
	"fmt"
	"strings"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type IssueCertificateCommand struct {
	TokenHash string
	CSR       []byte
}

type IssueCertificateResult struct {
	Enrollment  domainenrollment.Enrollment
	Certificate domainenrollment.Certificate
}

type IssueService struct {
	uow    ports.EnrollmentUnitOfWork
	issuer ports.CertificateIssuer
	clock  ports.Clock
}

func NewIssueService(uow ports.EnrollmentUnitOfWork, issuer ports.CertificateIssuer, clock ports.Clock) *IssueService {
	return &IssueService{uow: uow, issuer: issuer, clock: clock}
}

func (service *IssueService) Execute(ctx context.Context, command IssueCertificateCommand) (IssueCertificateResult, error) {
	if service == nil || service.uow == nil || service.issuer == nil || service.clock == nil {
		return IssueCertificateResult{}, failure.New(failure.Internal, "enrollment issue service is incomplete")
	}
	if strings.TrimSpace(command.TokenHash) == "" || len(command.CSR) == 0 {
		return IssueCertificateResult{}, failure.New(failure.InvalidArgument, "token and csr are required")
	}
	var pending IssueCertificateResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		current, err := tx.Enrollments().ByTokenHash(txCtx, command.TokenHash)
		if err != nil {
			return fmt.Errorf("get enrollment by token: %w", err)
		}
		issuance, err := service.issuer.Issue(txCtx, current, command.CSR)
		if err != nil {
			return fmt.Errorf("issue certificate: %w", err)
		}
		issued, certificate, err := current.Issue(issuance, service.clock.Now())
		if err != nil {
			return err
		}
		if err := tx.Enrollments().Put(txCtx, issued); err != nil {
			return fmt.Errorf("put enrollment: %w", err)
		}
		if err := tx.Certificates().Put(txCtx, certificate); err != nil {
			return fmt.Errorf("put certificate: %w", err)
		}
		pending = IssueCertificateResult{Enrollment: issued, Certificate: certificate}
		return nil
	})
	if err != nil {
		return IssueCertificateResult{}, err
	}
	return pending, nil
}
