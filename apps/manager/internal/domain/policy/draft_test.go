package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestManagerDefaultContainsCompleteEndpointPolicy(t *testing.T) {
	value := ManagerDefault(mustTenantID(t, "tenant-a"))
	for _, want := range []string{`"collection"`, `"detection"`, `"telemetry"`, `"response"`} {
		if !strings.Contains(string(value.DownlinkDocument), want) {
			t.Fatalf("ManagerDefault() downlink %s missing %s", value.DownlinkDocument, want)
		}
	}
	for _, want := range []string{
		`"collection"`, `"detection"`, `"telemetry"`, `"response_policy"`,
		`"cloud_rules"`, `"mode":"observe"`, `"converge"`,
	} {
		if !strings.Contains(string(value.Document), want) {
			t.Fatalf("ManagerDefault() document %s missing %s", value.Document, want)
		}
	}
}

func TestSaveRejectsExistingVersion(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "admin-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}

	_, _, err := Save(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 2},
		Policy{TenantID: tenantID, ID: "policy-a", Version: 2}, actor, time.Now(),
	)
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("Save() error kind = %q, want %q", failure.KindOf(err), failure.Conflict)
	}
}

func TestSaveAlwaysCreatesUnpublishedVersion(t *testing.T) {
	tenantID := mustTenantID(t, "tenant-a")
	actor := tenant.Actor{Subject: "admin-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin)}

	saved, _, err := Save(
		Policy{TenantID: tenantID, ID: "policy-a", Version: 1, Published: true},
		Policy{TenantID: tenantID, ID: "policy-a", Version: 2, Published: true}, actor, time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Published {
		t.Fatal("Save() allowed draft to bypass publication")
	}
}
