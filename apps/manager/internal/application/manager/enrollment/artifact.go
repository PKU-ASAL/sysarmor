package enrollment

import (
	"context"
	"fmt"
	"strings"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type AuthorizeArtifactCommand struct{ TokenHash string }

type AuthorizeArtifactResult struct {
	Enrollment domainenrollment.Enrollment
	Artifact   domainenrollment.InstallArtifact
}

type ArtifactService struct {
	uow   ports.EnrollmentUnitOfWork
	clock ports.Clock
}

func NewArtifactService(uow ports.EnrollmentUnitOfWork, clock ports.Clock) *ArtifactService {
	return &ArtifactService{uow: uow, clock: clock}
}

func (service *ArtifactService) Authorize(ctx context.Context, command AuthorizeArtifactCommand) (AuthorizeArtifactResult, error) {
	if service == nil || service.uow == nil || service.clock == nil {
		return AuthorizeArtifactResult{}, failure.New(failure.Internal, "artifact service is incomplete")
	}
	command.TokenHash = strings.TrimSpace(command.TokenHash)
	if command.TokenHash == "" {
		return AuthorizeArtifactResult{}, failure.New(failure.NotFound, "enrollment artifact not found")
	}
	var result AuthorizeArtifactResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		value, err := tx.Enrollments().ByTokenHash(txCtx, command.TokenHash)
		if err != nil {
			return fmt.Errorf("get artifact enrollment: %w", err)
		}
		artifactID, err := value.AuthorizeArtifact(service.clock.Now())
		if err != nil {
			return err
		}
		artifact, err := tx.InstallMaterials().GetArtifact(txCtx, value.TenantID, artifactID)
		if err != nil {
			return fmt.Errorf("get install artifact: %w", err)
		}
		result = AuthorizeArtifactResult{Enrollment: value, Artifact: artifact}
		return nil
	})
	return result, err
}
