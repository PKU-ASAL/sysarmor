package runtime

import (
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type responseContext struct {
	policy        *policyRuntime
	scopeType     string
	scopeSelector string
}

func newResponseContext(policy *policyRuntime, scopeType, scopeSelector string) *responseContext {
	return &responseContext{policy: policy, scopeType: scopeType, scopeSelector: scopeSelector}
}

func (r *responseContext) Identity() ports.ResponseIdentity {
	identity := r.policy.management.currentIdentity()
	return ports.ResponseIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *responseContext) Policy() domainresponse.Policy {
	policy := r.policy.activePolicy()
	response := policy.Response
	response.ID, response.Version = policy.PolicyID, policy.Version
	response.AllowedActions = append([]string(nil), response.AllowedActions...)
	response.AllowedModes = append([]domainresponse.Mode(nil), response.AllowedModes...)
	response.ApprovalRoles = append([]string(nil), response.ApprovalRoles...)
	return response
}

func (r *responseContext) Scope() (domainresponse.Scope, bool) {
	scope := domainresponse.Scope{Type: r.scopeType, Selector: r.scopeSelector}
	return scope, scope.Type != ""
}
