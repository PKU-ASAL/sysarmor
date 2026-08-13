package artifact

import (
	"context"
	"errors"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UploadCommand struct {
	Name     string
	Kind     string
	Version  string
	OS       string
	Arch     string
	Filename string
	Status   domainartifact.Status
	Content  ports.ArtifactReader
}

func (service *Service) Upload(ctx context.Context, request managerapp.RequestContext, command UploadCommand) (domainartifact.Artifact, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainartifact.Artifact{}, err
	}
	if err := service.requireArchive(); err != nil {
		return domainartifact.Artifact{}, err
	}
	archived, err := service.archive.Store(ctx, request.Actor.TenantID, archiveInput(command, request.Actor.Subject))
	if err != nil {
		return domainartifact.Artifact{}, err
	}
	value, err := domainartifact.New(artifactFromArchive(command, request, archived), service.clock.Now())
	if err != nil {
		return domainartifact.Artifact{}, service.removeAfterError(ctx, archived.StoragePath, err)
	}
	var result domainartifact.Artifact
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.ArtifactTransaction) error {
		var putErr error
		result, putErr = tx.Artifacts().Put(txCtx, value)
		return putErr
	})
	if err != nil {
		return domainartifact.Artifact{}, service.removeAfterError(ctx, archived.StoragePath, err)
	}
	return result, nil
}

func archiveInput(command UploadCommand, actor string) ports.ArtifactArchiveInput {
	return ports.ArtifactArchiveInput{Name: command.Name, Kind: command.Kind, Version: command.Version,
		OS: command.OS, Arch: command.Arch, Filename: command.Filename, CreatedBy: actor, Content: command.Content}
}

func artifactFromArchive(command UploadCommand, request managerapp.RequestContext, archived ports.ArchivedArtifact) domainartifact.Artifact {
	return domainartifact.Artifact{ID: archived.ID, TenantID: request.Actor.TenantID, Name: command.Name,
		Kind: command.Kind, Version: command.Version, OS: command.OS, Arch: command.Arch, SHA256: archived.SHA256,
		SizeBytes: archived.SizeBytes, Status: command.Status, StoragePath: archived.StoragePath,
		CreatedBy: request.Actor.Subject, Metadata: archived.Metadata}
}

func (service *Service) removeAfterError(ctx context.Context, path string, cause error) error {
	if err := service.archive.Remove(ctx, path); err != nil {
		return errors.Join(cause, fmt.Errorf("remove archived artifact: %w", err))
	}
	return cause
}
