package policy

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestAssignRejectsEmptyTarget(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}

	_, err := Assign(Policy{TenantID: tenantID, ID: "policy-a", Version: 1, Published: true}, Target{}, actor, time.Now())
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("Assign() error kind = %q, want %q", failure.KindOf(err), failure.InvalidArgument)
	}
}

func TestAssignRejectsUnpublishedPolicy(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}

	_, err := Assign(Policy{TenantID: tenantID, ID: "policy-a", Version: 1}, Target{AgentID: "agent-a"}, actor, time.Now())
	if failure.KindOf(err) != failure.FailedPrecondition {
		t.Fatalf("Assign() error kind = %q, want %q", failure.KindOf(err), failure.FailedPrecondition)
	}
}

func TestAssignRejectsAgentAndScopeTarget(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}

	_, err := Assign(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 1, Published: true},
		Target{AgentID: "agent-a", ScopeType: "label", ScopeSelector: "env=prod"}, actor, time.Now(),
	)
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("Assign() error kind = %q, want %q", failure.KindOf(err), failure.InvalidArgument)
	}
}

func TestAssignUsesSuppliedTime(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}
	now := time.Date(2026, 8, 8, 4, 5, 6, 0, time.UTC)

	assignment, err := Assign(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 3, Published: true},
		Target{AgentID: "agent-a"}, actor, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.TenantID != tenantID || assignment.PolicyID != "policy-a" || assignment.PolicyVersion != 3 {
		t.Fatalf("Assign() = %+v", assignment)
	}
	if !assignment.CreatedAt.Equal(now) || !assignment.UpdatedAt.Equal(now) {
		t.Fatalf("Assign() timestamps = %s / %s, want %s", assignment.CreatedAt, assignment.UpdatedAt, now)
	}
}

func TestAssignAllowsScopeTypeWithoutSelector(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}

	_, err := Assign(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 1, Published: true},
		Target{ScopeType: "host"}, actor, time.Now(),
	)
	if err != nil {
		t.Fatalf("Assign() rejected scope type target: %v", err)
	}
}
