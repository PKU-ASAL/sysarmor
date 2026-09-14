package control

import (
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) listEvidence(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	values, err := handler.options.Query.Evidence(request.Context(), requestContext, controlapp.EvidenceQuery{
		AgentID: request.URL.Query().Get("agent_id"),
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	documents := make([]evidenceDocument, 0, len(values))
	for _, value := range values {
		documents = append(documents, mapEvidence(value))
	}
	writeJSON(writer, documents)
}

func (handler *Handler) createEvidence(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	var body evidenceRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, fmt.Sprintf("decode evidence pullback: %v", err)))
		return
	}
	result, err := handler.options.Management.CreateEvidence(request.Context(), requestContext, controlapp.CreateEvidenceCommand{
		RequestID: body.RequestID, TenantID: body.TenantID, AgentID: body.AgentID,
		IncidentID: body.IncidentID, Labels: body.Labels, Target: body.Target, Reason: body.Reason,
	})
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, mapEvidence(result))
}
