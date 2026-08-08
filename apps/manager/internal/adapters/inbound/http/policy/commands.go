package policy

import (
	"encoding/json"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func (handler *Handler) savePolicy(w http.ResponseWriter, r *http.Request, request managerapp.RequestContext) {
	if err := request.Actor.Require(tenant.RoleAdmin); err != nil {
		writeFailure(w, err)
		return
	}
	var raw json.RawMessage
	if !decodeRequest(w, r, &raw) {
		return
	}
	var identity policyIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		writeFailure(w, err)
		return
	}
	result, err := handler.options.Save.Execute(r.Context(), request, policyapp.SavePolicyCommand{
		Policy: domainpolicy.Policy{
			TenantID: request.Actor.TenantID, ID: domainpolicy.ID(identity.PolicyID),
			Version: domainpolicy.Version(identity.Version), Published: identity.Published, Document: raw,
		},
		Reason: r.URL.Query().Get("reason"),
	})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, policyDocument(result.Policy))
}

func (handler *Handler) getPolicies(w http.ResponseWriter, r *http.Request, request managerapp.RequestContext) {
	query := r.URL.Query()
	if id := domainpolicy.ID(query.Get("policy_id")); id != "" {
		result, err := handler.options.Query.GetPolicy(r.Context(), request, policyapp.GetPolicyQuery{
			PolicyID: id, Version: domainpolicy.Version(parseUint(query.Get("version"))),
		})
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, policyDocument(result.Policy))
		return
	}
	result, err := handler.options.Query.ListPolicies(r.Context(), request, policyapp.ListPoliciesQuery{})
	if err != nil {
		writeFailure(w, err)
		return
	}
	documents := make([]any, 0, len(result.Policies))
	for _, value := range result.Policies {
		documents = append(documents, policyDocument(value))
	}
	writeJSON(w, documents)
}

func (handler *Handler) assignPolicy(w http.ResponseWriter, r *http.Request, request managerapp.RequestContext) {
	if err := request.Actor.Require(tenant.RoleAdmin); err != nil {
		writeFailure(w, err)
		return
	}
	var body assignmentRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	result, err := handler.options.Assign.Execute(r.Context(), request, policyapp.AssignPolicyCommand{
		AssignmentID: body.AssignmentID, PolicyID: domainpolicy.ID(body.PolicyID), Version: domainpolicy.Version(body.PolicyVersion),
		Target:   domainpolicy.Target{AgentID: body.AgentID, ScopeType: body.Scope.Type, ScopeSelector: body.Scope.Selector},
		Downlink: body.Downlink, CommandID: body.CommandID, Reason: body.Reason,
	})
	if err != nil {
		writeFailure(w, err)
		return
	}
	assignment := assignmentDocument(result.Assignment)
	if result.Control == nil {
		writeJSON(w, assignment)
		return
	}
	writeJSON(w, map[string]any{"assignment": assignment, "control_command": controlDocument(*result.Control)})
}
