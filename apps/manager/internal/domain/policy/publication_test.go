package policy

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestPublishRejectsStaleVersion(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}
	current := Policy{TenantID: tenantID, ID: "policy-a", Version: 2}
	candidate := Policy{TenantID: tenantID, ID: "policy-a", Version: 1}

	_, _, err := Publish(current, candidate, actor, time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC))
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("Publish() error kind = %q, want %q", failure.KindOf(err), failure.Conflict)
	}
}

func TestPublishRejectsTenantMismatch(t *testing.T) {
	tenantA := mustTenantID(t, "tenant-a")
	tenantB := mustTenantID(t, "tenant-b")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantA, Roles: tenant.NewRoleSet(tenant.RoleOperator)}

	_, _, err := Publish(
		Policy{TenantID: tenantA, ID: "policy-a", Version: 1},
		Policy{TenantID: tenantB, ID: "policy-a", Version: 2},
		actor,
		time.Now(),
	)
	if failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("Publish() error kind = %q, want %q", failure.KindOf(err), failure.PermissionDenied)
	}
}

func TestPublishReturnsDeterministicImmutableAudit(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}
	now := time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)
	candidate := Policy{TenantID: tenantID, ID: "policy-a", Version: 2, Published: true}

	published, audit, err := Publish(Policy{TenantID: tenantID, ID: "policy-a", Version: 1}, candidate, actor, now)
	if err != nil {
		t.Fatal(err)
	}
	candidate.ID = "changed"
	if !published.Published || !published.UpdatedAt.Equal(now) {
		t.Fatalf("Publish() policy = %+v", published)
	}
	if audit.PolicyID != "policy-a" || audit.PolicyVersion != 2 || audit.Actor != "operator-a" || !audit.OccurredAt.Equal(now) {
		t.Fatalf("Publish() audit = %+v", audit)
	}
}

func TestPublishCanUnpublishPolicy(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator)}
	now := time.Date(2026, 8, 8, 1, 2, 3, 0, time.UTC)

	updated, record, err := Publish(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 2, Published: true},
		Policy{TenantID: tenantID, ID: "policy-a", Version: 2, Published: false},
		actor, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Published || record.Action != "policy.unpublish" {
		t.Fatalf("Publish() = policy %+v, audit %+v", updated, record)
	}
}

func mustTenantID(t *testing.T, value string) tenant.ID {
	t.Helper()
	id, err := tenant.NewID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
