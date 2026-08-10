package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type PublishPolicy interface {
	Execute(context.Context, managerapp.RequestContext, policyapp.PublishPolicyCommand) (policyapp.PublishPolicyResult, error)
}

type AssignPolicy interface {
	Execute(context.Context, managerapp.RequestContext, policyapp.AssignPolicyCommand) (policyapp.AssignPolicyResult, error)
}

type SavePolicy interface {
	Execute(context.Context, managerapp.RequestContext, policyapp.SavePolicyCommand) (policyapp.SavePolicyResult, error)
}

type PolicyQueries interface {
	ListRules(context.Context, managerapp.RequestContext, domainpolicy.RuleFilter) ([]domainpolicy.Rule, error)
	GetPolicy(context.Context, managerapp.RequestContext, policyapp.GetPolicyQuery) (policyapp.GetPolicyResult, error)
	ListPolicies(context.Context, managerapp.RequestContext, policyapp.ListPoliciesQuery) (policyapp.ListPoliciesResult, error)
	ListAssignments(context.Context, managerapp.RequestContext, domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error)
	ListAudits(context.Context, managerapp.RequestContext, domainpolicy.ID) ([]audit.Record, error)
	EffectivePolicy(context.Context, managerapp.RequestContext, policyapp.EffectivePolicyQuery) (policyapp.EffectivePolicyResult, error)
}

type RolloutQueries interface {
	List(context.Context, managerapp.RequestContext, policyapp.RolloutQuery) ([]policyapp.Rollout, error)
}

type Options struct {
	Publish PublishPolicy
	Assign  AssignPolicy
	Save    SavePolicy
	Query   PolicyQueries
	Rollout RolloutQueries
	Resolve RequestContextResolver
}

type Handler struct{ options Options }

func NewHandler(options Options) *Handler { return &Handler{options: options} }

func (handler *Handler) Policies(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		handler.getPolicies(w, r, request)
	case http.MethodPost:
		handler.savePolicy(w, r, request)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (handler *Handler) Rules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	values, err := handler.options.Query.ListRules(r.Context(), request,
		domainpolicy.RuleFilter{Where: r.URL.Query().Get("where")})
	if err != nil {
		writeFailure(w, err)
		return
	}
	documents := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		documents = append(documents, json.RawMessage(value.Document))
	}
	writeJSON(w, documents)
}

func (handler *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := handler.resolveAdmin(w, r)
	if !ok {
		return
	}
	var body publishRequest
	if !decodeRequest(w, r, &body) {
		return
	}
	result, err := handler.options.Publish.Execute(r.Context(), request, policyapp.PublishPolicyCommand{
		PolicyID: domainpolicy.ID(body.PolicyID), Version: domainpolicy.Version(body.Version),
		Published: body.Published, Reason: body.Reason,
	})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, policyDocument(result.Policy))
}

func (handler *Handler) Audits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	values, err := handler.options.Query.ListAudits(r.Context(), request, domainpolicy.ID(r.URL.Query().Get("policy_id")))
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, auditDocuments(values))
}

func (handler *Handler) Assignments(w http.ResponseWriter, r *http.Request) {
	request, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		values, err := handler.options.Query.ListAssignments(r.Context(), request, domainpolicy.AssignmentFilter{AgentID: r.URL.Query().Get("agent_id")})
		if err != nil {
			writeFailure(w, err)
			return
		}
		writeJSON(w, assignmentDocuments(values))
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	handler.assignPolicy(w, r, request)
}

func (handler *Handler) Effective(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := handler.resolve(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	result, err := handler.options.Query.EffectivePolicy(r.Context(), request, policyapp.EffectivePolicyQuery{Target: domainpolicy.Target{
		AgentID: query.Get("agent_id"), ScopeType: query.Get("scope_type"), ScopeSelector: query.Get("scope_selector"),
	}})
	if err != nil {
		writeFailure(w, err)
		return
	}
	writeJSON(w, policyDocument(result.Policy))
}

func (handler *Handler) resolve(w http.ResponseWriter, r *http.Request) (managerapp.RequestContext, bool) {
	if handler.options.Resolve == nil {
		writeFailure(w, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	request, err := handler.options.Resolve(r)
	if err != nil {
		writeFailure(w, err)
		return managerapp.RequestContext{}, false
	}
	return request, true
}

func (handler *Handler) resolveAdmin(w http.ResponseWriter, r *http.Request) (managerapp.RequestContext, bool) {
	request, ok := handler.resolve(w, r)
	if !ok {
		return managerapp.RequestContext{}, false
	}
	if err := request.Actor.Require(tenant.RoleAdmin); err != nil {
		writeFailure(w, err)
		return managerapp.RequestContext{}, false
	}
	return request, true
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		http.Error(w, fmt.Sprintf("decode request: %v", err), http.StatusBadRequest)
		return false
	}
	return true
}

func writeFailure(w http.ResponseWriter, err error) {
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
	http.Error(w, err.Error(), status)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
