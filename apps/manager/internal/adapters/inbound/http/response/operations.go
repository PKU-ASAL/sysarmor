package response

import (
	"encoding/json"
	"net/http"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func (handler *Handler) list(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	pending := request.URL.Query().Get("pending") == "true"
	values, err := handler.options.Service.List(request.Context(), requestContext, responseapp.Query{
		AgentID: request.URL.Query().Get("agent_id"), Pending: pending,
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	if pending {
		documents := make([]commandDocument, 0, len(values))
		for _, value := range values {
			documents = append(documents, mapCommand(value))
		}
		writeJSON(writer, documents)
		return
	}
	documents := make([]auditDocument, 0, len(values))
	for _, value := range values {
		documents = append(documents, mapAudit(value))
	}
	writeJSON(writer, documents)
}

func (handler *Handler) create(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body commandRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, "decode response command: "+err.Error()))
		return
	}
	handler.createCommand(writer, request, requestContext, mapRequest(body))
}

func (handler *Handler) createCommand(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext, command domainresponse.Command) {
	if strings.TrimSpace(command.AgentID) == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "agent_id is required"))
		return
	}
	result, err := handler.options.Service.Create(request.Context(), requestContext, command)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writePrepareResult(writer, result)
}

func writePrepareResult(writer http.ResponseWriter, result domainresponse.PrepareResult) {
	if !result.Allowed {
		writer.WriteHeader(http.StatusForbidden)
		writeJSON(writer, mapAudit(result.Command))
		return
	}
	writeJSON(writer, mapCommand(result.Command))
}

func (handler *Handler) approve(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body approvalRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, "decode response approval: "+err.Error()))
		return
	}
	if strings.TrimSpace(body.ResponseID) == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "response_id is required"))
		return
	}
	role := string(tenant.RoleOperator)
	if requestContext.Actor.Roles.Has(tenant.RoleAdmin) {
		role = string(tenant.RoleAdmin)
	}
	value, err := handler.options.Service.Approve(request.Context(), requestContext, responseapp.ApprovalCommand{
		TenantID: body.TenantID, ResponseID: body.ResponseID, AgentID: body.AgentID,
		Approved: body.Approved, Role: role, Reason: body.Reason,
	})
	if err != nil {
		writeApprovalFailure(writer, err)
		return
	}
	writeJSON(writer, mapAudit(value))
}

func writeApprovalFailure(writer http.ResponseWriter, err error) {
	switch failure.KindOf(err) {
	case failure.PermissionDenied, failure.FailedPrecondition:
		http.Error(writer, "response command not found", http.StatusNotFound)
	default:
		writeFailure(writer, err)
	}
}

func (handler *Handler) acknowledge(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	if err := requestContext.Actor.Require(tenant.RoleOperator); err != nil {
		writeFailure(writer, err)
		return
	}
	var body acknowledgementDocument
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, "decode response ack: "+err.Error()))
		return
	}
	if strings.TrimSpace(body.AgentID) == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "agent_id is required"))
		return
	}
	body.TenantID = requestContext.Actor.TenantID.String()
	_, err := handler.options.Service.Acknowledge(request.Context(), responseapp.AcknowledgeCommand{
		TenantID: body.TenantID, ResponseID: body.ResponseID, AgentID: body.AgentID, Accepted: body.Accepted,
		Unsupported: body.Unsupported, ObserveOnly: body.ObserveOnly, Executed: body.Executed,
		Message: body.Message, ObservedAt: body.ObservedAt,
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"ok": true})
}

func (handler *Handler) createDecision(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body decisionRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, "decode response decision: "+err.Error()))
		return
	}
	result, err := handler.options.Service.Decide(request.Context(), requestContext, responseapp.DecisionCommand{
		SignalID: body.SignalID, TenantID: body.TenantID, AgentID: body.AgentID,
		Scope: domainresponse.Scope{Type: body.Scope.Type, Selector: body.Scope.Selector}, Target: body.Target,
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writePrepareResult(writer, result)
}
