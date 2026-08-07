package tenant

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func TestNewIDTrimsWhitespace(t *testing.T) {
	id, err := NewID("  tenant-a  ")
	if err != nil {
		t.Fatal(err)
	}
	if id.String() != "tenant-a" {
		t.Fatalf("ID.String() = %q, want tenant-a", id.String())
	}
}

func TestNewIDRejectsBlank(t *testing.T) {
	if _, err := NewID("  "); failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("NewID() error kind = %q, want %q", failure.KindOf(err), failure.InvalidArgument)
	}
}

func TestActorRequireAcceptsAdminForOperator(t *testing.T) {
	tenantID, err := NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{TenantID: tenantID, Roles: NewRoleSet(RoleAdmin)}
	if err := actor.Require(RoleOperator); err != nil {
		t.Fatal(err)
	}
}

func TestActorRequireRejectsMissingRole(t *testing.T) {
	tenantID, err := NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{TenantID: tenantID, Roles: NewRoleSet(RoleViewer)}
	if err := actor.Require(RoleOperator); failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("Actor.Require() error kind = %q, want %q", failure.KindOf(err), failure.PermissionDenied)
	}
}
