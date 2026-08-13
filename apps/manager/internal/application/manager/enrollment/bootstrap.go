package enrollment

import (
	"context"
	"fmt"
	"strings"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type RedeemBootstrapCommand struct{ TicketHash string }

type RedeemBootstrapResult struct {
	Enrollment domainenrollment.Enrollment
	Token      string
}

type BootstrapService struct {
	uow    ports.EnrollmentUnitOfWork
	tokens ports.EnrollmentTokenGenerator
	clock  ports.Clock
}

func NewBootstrapService(uow ports.EnrollmentUnitOfWork, tokens ports.EnrollmentTokenGenerator, clock ports.Clock) *BootstrapService {
	return &BootstrapService{uow: uow, tokens: tokens, clock: clock}
}

func (service *BootstrapService) Redeem(ctx context.Context, command RedeemBootstrapCommand) (RedeemBootstrapResult, error) {
	if service == nil || service.uow == nil || service.tokens == nil || service.clock == nil {
		return RedeemBootstrapResult{}, failure.New(failure.Internal, "bootstrap service is incomplete")
	}
	command.TicketHash = strings.TrimSpace(command.TicketHash)
	if command.TicketHash == "" {
		return RedeemBootstrapResult{}, failure.New(failure.InvalidArgument, "bootstrap ticket is required")
	}
	token, err := service.tokens.New()
	if err != nil {
		return RedeemBootstrapResult{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	var pending RedeemBootstrapResult
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		current, err := tx.Enrollments().ByBootstrapTokenHash(txCtx, command.TicketHash)
		if err != nil {
			return fmt.Errorf("get bootstrap enrollment: %w", err)
		}
		value, err := current.RedeemBootstrap(command.TicketHash, token.Hash, token.Preview, service.clock.Now())
		if err != nil {
			return err
		}
		if err := tx.Enrollments().RedeemBootstrap(txCtx, current, value); err != nil {
			return fmt.Errorf("put bootstrap enrollment: %w", err)
		}
		pending = RedeemBootstrapResult{Enrollment: value, Token: token.Plaintext}
		return nil
	})
	if err != nil {
		return RedeemBootstrapResult{}, err
	}
	return pending, nil
}
