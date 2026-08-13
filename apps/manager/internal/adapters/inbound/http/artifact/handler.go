package artifact

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Service interface {
	Upload(context.Context, managerapp.RequestContext, artifactapp.UploadCommand) (domainartifact.Artifact, error)
	ChangeStatus(context.Context, managerapp.RequestContext, artifactapp.ChangeStatusCommand) (domainartifact.Artifact, error)
	SetChannel(context.Context, managerapp.RequestContext, artifactapp.SetChannelCommand) (domainartifact.Channel, error)
	ListArtifacts(context.Context, managerapp.RequestContext, artifactapp.ArtifactQuery) ([]domainartifact.Artifact, error)
	GetArtifact(context.Context, managerapp.RequestContext, string) (domainartifact.Artifact, error)
	ListChannels(context.Context, managerapp.RequestContext) ([]domainartifact.Channel, error)
	GetChannel(context.Context, managerapp.RequestContext, string) (domainartifact.Channel, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Content ports.ArtifactContentReader
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) resolve(writer http.ResponseWriter, request *http.Request) (managerapp.RequestContext, bool) {
	if handler == nil || handler.options.Resolve == nil {
		writeFailure(writer, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	requestContext, err := handler.options.Resolve(request)
	if err != nil {
		writeFailure(writer, err)
		return managerapp.RequestContext{}, false
	}
	if handler.options.Service == nil {
		writeFailure(writer, failure.New(failure.Internal, "artifact service is not configured"))
		return managerapp.RequestContext{}, false
	}
	return requestContext, true
}

func writeFailure(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch failure.KindOf(err) {
	case failure.InvalidArgument, failure.FailedPrecondition:
		status = http.StatusBadRequest
	case failure.Unauthenticated:
		status = http.StatusUnauthorized
	case failure.PermissionDenied:
		status = http.StatusForbidden
	case failure.NotFound:
		status = http.StatusNotFound
	case failure.Conflict:
		status = http.StatusConflict
	}
	http.Error(writer, err.Error(), status)
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		http.Error(writer, fmt.Sprintf("encode response: %v", err), http.StatusInternalServerError)
	}
}
