package daemon

import (
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

type responseContext struct {
	runner        *AgentRuntime
	scopeType     string
	scopeSelector string
}

func newResponseContext(runner *AgentRuntime, scopeType, scopeSelector string) *responseContext {
	return &responseContext{runner: runner, scopeType: scopeType, scopeSelector: scopeSelector}
}

func (r *responseContext) Identity() ports.ResponseIdentity {
	identity := r.runner.currentIdentity()
	return ports.ResponseIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *responseContext) Policy() domainresponse.Policy {
	policy := r.runner.activePolicy()
	return domainResponsePolicy(policy.PolicyID, policy.Version, policy.Response)
}

func (r *responseContext) Scope() (domainresponse.Scope, bool) {
	scope := domainresponse.Scope{Type: r.scopeType, Selector: r.scopeSelector}
	return scope, scope.Type != ""
}

func domainResponsePolicy(id string, version uint64, policy responsemodel.Policy) domainresponse.Policy {
	modes := make([]domainresponse.Mode, 0, len(policy.AllowedModes))
	for _, mode := range policy.AllowedModes {
		modes = append(modes, domainresponse.Mode(mode))
	}
	return domainresponse.Policy{
		ID: id, Version: version,
		AllowedActions: append([]string(nil), policy.AllowedActions...), AllowedModes: modes,
		ApprovalRequired: policy.ApprovalRequired, ApprovalThreshold: policy.ApprovalThreshold,
		ApprovalRoles: append([]string(nil), policy.ApprovalRoles...), AllowDestructive: policy.AllowDestructive,
	}
}
