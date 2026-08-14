package runtime

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestResponseContextProjectsIdentityPolicyAndScope(t *testing.T) {
	runner := &Runtime{
		Config: config.Config{Agent: config.AgentConfig{TenantID: "local", ID: "device-a"}},
		Sensor: &healthOnlySensor{health: contract.Health{Backend: "fake"}},
	}
	runner.setPolicy(runner.activePolicy())
	runner.policy.Response = domainresponse.Policy{
		AllowedActions: []string{"kill"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce}, AllowDestructive: true,
	}
	runner.setRuntimeIdentity(runtimeIdentity{TenantID: "tenant-a", AgentID: "agent-a"})
	responseContext := newResponseContext(runner, "container", "abc123")
	if identity := responseContext.Identity(); identity.TenantID != "tenant-a" || identity.AgentID != "agent-a" {
		t.Fatalf("identity=%+v", identity)
	}
	if policy := responseContext.Policy(); !policy.AllowDestructive || policy.AllowedModes[0] != domainresponse.ModeEnforce {
		t.Fatalf("policy=%+v", policy)
	}
	if scope, ok := responseContext.Scope(); !ok || scope.Type != "container" || scope.Selector != "abc123" {
		t.Fatalf("scope=%+v ok=%t", scope, ok)
	}
}

func TestResponseContextPolicyIsIsolatedFromActivePolicy(t *testing.T) {
	runner := &Runtime{
		Config: config.Config{Agent: config.AgentConfig{TenantID: "local", ID: "device-a"}},
		Sensor: &healthOnlySensor{health: contract.Health{Backend: "fake"}},
	}
	runner.setPolicy(runner.activePolicy())
	runner.policy.Response = domainresponse.Policy{
		AllowedActions: []string{"kill"},
		AllowedModes:   []domainresponse.Mode{domainresponse.ModeEnforce},
		ApprovalRoles:  []string{"operator"},
	}

	projected := newResponseContext(runner, "", "").Policy()
	projected.AllowedActions[0] = "noop"
	projected.AllowedModes[0] = domainresponse.ModeObserve
	projected.ApprovalRoles[0] = "viewer"

	active := runner.activePolicy().Response
	if active.AllowedActions[0] != "kill" || active.AllowedModes[0] != domainresponse.ModeEnforce || active.ApprovalRoles[0] != "operator" {
		t.Fatalf("active response policy mutated: %+v", active)
	}
}
