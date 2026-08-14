package runtime

import (
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type responseContext struct {
	runner        *Runtime
	scopeType     string
	scopeSelector string
}

func newResponseContext(runner *Runtime, scopeType, scopeSelector string) *responseContext {
	return &responseContext{runner: runner, scopeType: scopeType, scopeSelector: scopeSelector}
}

func (r *responseContext) Identity() ports.ResponseIdentity {
	identity := r.runner.currentIdentity()
	return ports.ResponseIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *responseContext) Policy() domainresponse.Policy {
	policy := r.runner.activePolicy()
	response := policy.Response
	response.ID, response.Version = policy.PolicyID, policy.Version
	return response
}

func (r *responseContext) Scope() (domainresponse.Scope, bool) {
	scope := domainresponse.Scope{Type: r.scopeType, Selector: r.scopeSelector}
	return scope, scope.Type != ""
}
