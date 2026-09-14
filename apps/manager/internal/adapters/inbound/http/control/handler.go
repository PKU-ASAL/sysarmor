package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type ManagementService interface {
	CreateCommand(context.Context, managerapp.RequestContext, controlapp.CreateCommand) (domaincontrol.Command, error)
	CreateEvidence(context.Context, managerapp.RequestContext, controlapp.CreateEvidenceCommand) (domaincontrol.EvidencePullback, error)
	Act(context.Context, managerapp.RequestContext, controlapp.ActionCommand) (domaincontrol.Command, error)
}

type QueryService interface {
	Commands(context.Context, managerapp.RequestContext, controlapp.CommandQuery) ([]domaincontrol.Command, error)
	Evidence(context.Context, managerapp.RequestContext, controlapp.EvidenceQuery) ([]domaincontrol.EvidencePullback, error)
}

type PolicyPayloadResolver interface {
	Resolve(context.Context, managerapp.RequestContext, string, uint64) ([]byte, string, uint64, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Management ManagementService
	Query      QueryService
	Policies   PolicyPayloadResolver
	Resolve    RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Commands(writer http.ResponseWriter, request *http.Request) {
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		handler.listCommands(writer, request, requestContext)
	case http.MethodPost:
		handler.writeCommand(writer, request, requestContext)
	default:
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (handler *Handler) Evidence(writer http.ResponseWriter, request *http.Request) {
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		handler.listEvidence(writer, request, requestContext)
	case http.MethodPost:
		handler.createEvidence(writer, request, requestContext)
	default:
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (handler *Handler) resolve(writer http.ResponseWriter, request *http.Request) (managerapp.RequestContext, bool) {
	if handler.options.Resolve == nil {
		writeFailure(writer, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	value, err := handler.options.Resolve(request)
	if err != nil {
		writeFailure(writer, err)
		return managerapp.RequestContext{}, false
	}
	return value, true
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
