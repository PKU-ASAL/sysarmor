package policy

import (
	"context"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestListRolloutsUsesAuthenticatedTenantAndAggregatesState(t *testing.T) {
	tenantID := mustPolicyTenant(t, "tenant-a")
	request := managerapp.RequestContext{Actor: tenant.Actor{TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
	identity := &rolloutIdentityFake{
		agents: []domainidentity.AgentView{
			{Agent: domainidentity.Agent{TenantID: tenantID, ID: "agent-a"}},
			{Agent: domainidentity.Agent{TenantID: tenantID, ID: "agent-b"}},
		},
		health: []domainidentity.Health{
			{TenantID: tenantID, AgentID: "agent-a", AppliedPolicy: domainidentity.PolicyRef{ID: "old-policy", Version: 1},
				PendingPolicy: domainidentity.PendingPolicy{Status: "pending", ID: "policy-a", Version: 3}},
			{TenantID: tenantID, AgentID: "agent-b", AppliedPolicy: domainidentity.PolicyRef{ID: "old-policy", Version: 1},
				PendingPolicy: domainidentity.PendingPolicy{Status: "pending", ID: "policy-a", Version: 3}},
		},
	}
	policies := &rolloutPolicyFake{
		assignments: []domainpolicy.Assignment{
			{TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"}, PolicyID: "policy-a", PolicyVersion: 3},
			{TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-b"}, PolicyID: "policy-a", PolicyVersion: 3},
		},
		policies: []domainpolicy.Policy{{TenantID: tenantID, ID: "policy-a", Version: 3, Published: true}},
	}
	controls := &rolloutControlFake{}

	result, err := NewRolloutService(identity, policies, controls).List(context.Background(), request, RolloutQuery{Status: "pending"})

	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 || result[0].TenantID != tenantID || result[0].AgentID != "agent-a" || result[0].Status != "pending" || !result[0].Drift {
		t.Fatalf("rollouts = %+v", result)
	}
	if identity.observedTenant != tenantID || policies.observedTenant != tenantID || controls.observedTenant != tenantID {
		t.Fatalf("observed tenants identity=%q policy=%q control=%q", identity.observedTenant, policies.observedTenant, controls.observedTenant)
	}
	if identity.healthCalls != 1 || policies.effectiveCalls != 1 || controls.calls != 1 {
		t.Fatalf("query amplification health=%d effective=%d control=%d", identity.healthCalls, policies.effectiveCalls, controls.calls)
	}
}

func TestRolloutStatusPreservesPrecedence(t *testing.T) {
	tests := []struct {
		name               string
		rollout            Rollout
		hasHealth, command bool
		want               string
	}{
		{name: "applied before failed command", rollout: Rollout{DesiredPolicyID: "p", DesiredPolicyVersion: 2, AppliedPolicyID: "p", AppliedPolicyVersion: 2, CommandStatus: string(domaincontrol.CommandFailed)}, hasHealth: true, command: true, want: "applied"},
		{name: "failed", rollout: Rollout{CommandStatus: string(domaincontrol.CommandRejected)}, hasHealth: true, command: true, want: "failed"},
		{name: "expired", rollout: Rollout{CommandStatus: string(domaincontrol.CommandExpired)}, hasHealth: true, command: true, want: "failed"},
		{name: "pending command", rollout: Rollout{CommandStatus: string(domaincontrol.CommandSent)}, command: true, want: "pending"},
		{name: "pending health", rollout: Rollout{DesiredPolicyID: "p", DesiredPolicyVersion: 2, PendingPolicy: domainidentity.PendingPolicy{ID: "p", Version: 2}}, hasHealth: true, want: "pending"},
		{name: "drifted", rollout: Rollout{Drift: true}, hasHealth: true, want: "drifted"},
		{name: "unknown", rollout: Rollout{}, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rolloutStatus(tt.rollout, tt.hasHealth, tt.command); got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLatestPolicyCommandUsesUpdatedTimeAsTieBreaker(t *testing.T) {
	created := time.Unix(1, 0)
	commands := []domaincontrol.Command{
		{ID: "older", PolicyID: "policy-a", PolicyVersion: 3, CreatedAt: created, UpdatedAt: created},
		{ID: "newer", PolicyID: "policy-a", PolicyVersion: 3, CreatedAt: created, UpdatedAt: created.Add(time.Second)},
	}
	command, ok := latestPolicyCommand(commands, "policy-a", 3)
	if !ok || command.ID != "newer" {
		t.Fatalf("latest command = %+v, found=%t", command, ok)
	}
}

func TestResolveRolloutPolicyUsesPublishedAssignmentPrecedence(t *testing.T) {
	tenantID := mustPolicyTenant(t, "tenant-a")
	now := time.Unix(10, 0)
	assignments := []domainpolicy.Assignment{
		{ID: "global", TenantID: tenantID, PolicyID: "global-policy", PolicyVersion: 1},
		{ID: "older", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"}, PolicyID: "older-policy", PolicyVersion: 1, UpdatedAt: now},
		{ID: "newer", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"}, PolicyID: "newer-policy", PolicyVersion: 2, UpdatedAt: now.Add(time.Second)},
	}
	policies := []domainpolicy.Policy{
		{TenantID: tenantID, ID: "global-policy", Version: 1, Published: true},
		{TenantID: tenantID, ID: "older-policy", Version: 1, Published: true},
		{TenantID: tenantID, ID: "newer-policy", Version: 2, Published: true},
	}
	if got := resolveRolloutPolicy(tenantID, "agent-a", assignments, policies); got.ID != "newer-policy" {
		t.Fatalf("effective policy = %+v", got)
	}
}

type rolloutIdentityFake struct {
	agents         []domainidentity.AgentView
	health         []domainidentity.Health
	observedTenant tenant.ID
	healthCalls    int
}

func (fake *rolloutIdentityFake) ListAgents(_ context.Context, request managerapp.RequestContext, _ identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error) {
	fake.observedTenant = request.Actor.TenantID
	return identityapp.ListAgentsResult{Agents: fake.agents}, nil
}

func (fake *rolloutIdentityFake) ListHealth(_ context.Context, request managerapp.RequestContext, _ identityapp.ListHealthQuery) (identityapp.ListHealthResult, error) {
	fake.observedTenant = request.Actor.TenantID
	fake.healthCalls++
	return identityapp.ListHealthResult{Health: fake.health}, nil
}

type rolloutPolicyFake struct {
	assignments    []domainpolicy.Assignment
	policies       []domainpolicy.Policy
	observedTenant tenant.ID
	effectiveCalls int
}

func (fake *rolloutPolicyFake) ListAssignments(_ context.Context, request managerapp.RequestContext, _ domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error) {
	fake.observedTenant = request.Actor.TenantID
	return fake.assignments, nil
}

func (fake *rolloutPolicyFake) ListPolicies(_ context.Context, request managerapp.RequestContext, _ ListPoliciesQuery) (ListPoliciesResult, error) {
	fake.observedTenant = request.Actor.TenantID
	fake.effectiveCalls++
	return ListPoliciesResult{Policies: fake.policies}, nil
}

type rolloutControlFake struct {
	observedTenant tenant.ID
	calls          int
}

func (fake *rolloutControlFake) Commands(_ context.Context, request managerapp.RequestContext, _ controlapp.CommandQuery) ([]domaincontrol.Command, error) {
	fake.observedTenant = request.Actor.TenantID
	fake.calls++
	return []domaincontrol.Command{{ID: "command-a", TenantID: request.Actor.TenantID, AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 3, Status: domaincontrol.CommandSent, CreatedAt: time.Unix(1, 0)}}, nil
}

func mustPolicyTenant(t *testing.T, value string) tenant.ID {
	t.Helper()
	id, err := tenant.NewID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
