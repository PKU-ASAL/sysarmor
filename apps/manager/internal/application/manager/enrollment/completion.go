package enrollment

import (
	"context"
	"fmt"
	"strings"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CompleteUnenrollmentCommand struct {
	Identity  domainenrollment.UnenrollmentIdentity
	Receipt   string
	TokenHash string
}

type CompleteUnenrollmentResult struct{ Unenrollment domainenrollment.Unenrollment }

type CompletionService struct {
	uow   ports.EnrollmentUnitOfWork
	clock ports.Clock
}

func NewCompletionService(uow ports.EnrollmentUnitOfWork, clock ports.Clock) *CompletionService {
	return &CompletionService{uow: uow, clock: clock}
}

func (service *CompletionService) Execute(ctx context.Context, command CompleteUnenrollmentCommand) (CompleteUnenrollmentResult, error) {
	if service == nil || service.uow == nil || service.clock == nil {
		return CompleteUnenrollmentResult{}, failure.New(failure.Internal, "unenrollment completion service is incomplete")
	}
	if command.Identity.TenantID == "" || strings.TrimSpace(command.Identity.EnrollmentID) == "" {
		return CompleteUnenrollmentResult{}, failure.New(failure.InvalidArgument, "unenrollment identity is required")
	}
	var pending CompleteUnenrollmentResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		current, err := tx.Unenrollments().Get(txCtx, command.Identity.TenantID, command.Identity.EnrollmentID)
		if err != nil {
			return fmt.Errorf("get unenrollment: %w", err)
		}
		completed, err := current.Complete(domainenrollment.UnenrollmentCompletion{
			Identity: command.Identity, Receipt: command.Receipt, TokenHash: command.TokenHash,
		}, service.clock.Now())
		if err != nil {
			return err
		}
		if err := tx.Unenrollments().Put(txCtx, completed); err != nil {
			return fmt.Errorf("put unenrollment: %w", err)
		}
		pending.Unenrollment = completed
		return nil
	})
	if err != nil {
		return CompleteUnenrollmentResult{}, err
	}
	return pending, nil
}
