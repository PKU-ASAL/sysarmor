package response

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
)

type Service interface {
	Create(context.Context, managerapp.RequestContext, domainresponse.Command) (domainresponse.PrepareResult, error)
	Decide(context.Context, managerapp.RequestContext, responseapp.DecisionCommand) (domainresponse.PrepareResult, error)
	Approve(context.Context, managerapp.RequestContext, responseapp.ApprovalCommand) (domainresponse.Command, error)
	Acknowledge(context.Context, responseapp.AcknowledgeCommand) (domainresponse.Acknowledged, error)
	List(context.Context, managerapp.RequestContext, responseapp.Query) ([]domainresponse.Command, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Options struct {
	Service Service
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Responses(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		handler.list(writer, request, requestContext)
	case http.MethodPost:
		handler.create(writer, request, requestContext)
	}
}

func (handler *Handler) Decisions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	handler.createDecision(writer, request, requestContext)
}

func (handler *Handler) Approvals(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if ok {
		handler.approve(writer, request, requestContext)
	}
}

func (handler *Handler) Acknowledgements(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolve(writer, request)
	if ok {
		handler.acknowledge(writer, request, requestContext)
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
