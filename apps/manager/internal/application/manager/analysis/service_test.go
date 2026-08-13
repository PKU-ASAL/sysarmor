package analysis

import (
	"context"
	"errors"
	"testing"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestRecomputeUsesAuthenticatedTenantAndAnalysisPolicy(t *testing.T) {
	fixture := newFixture(t)
	result, err := fixture.service.Recompute(context.Background(), fixture.request, Query{
		Target: domainpolicy.Target{AgentID: "agent-a"}, Labels: map[string]string{"scenario": "one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.signals.tenantID != fixture.request.Actor.TenantID || fixture.policy.request.Actor.TenantID != fixture.request.Actor.TenantID {
		t.Fatalf("policy tenant = %q, signal tenant = %q", fixture.policy.request.Actor.TenantID, fixture.signals.tenantID)
	}
	if fixture.signals.filter.Labels["scenario"] != "one" || fixture.signals.filter.Layer != "endpoint" {
		t.Fatalf("signal filter = %+v", fixture.signals.filter)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Converge.Score != 90 {
		t.Fatalf("analysis = %+v", result)
	}
}

func TestRecomputeCanDisableCrossLineage(t *testing.T) {
	fixture := newFixture(t)
	result, err := fixture.service.Recompute(context.Background(), fixture.request, Query{Disable: "cloud.cross_lineage"})
	if err != nil || len(result.Incidents) != 0 {
		t.Fatalf("analysis = %+v, error = %v", result, err)
	}
}

func TestRecomputeRejectsUnknownControls(t *testing.T) {
	fixture := newFixture(t)
	for _, query := range []Query{{Disable: "unknown"}, {Mode: "unknown"}} {
		if _, err := fixture.service.Recompute(context.Background(), fixture.request, query); err == nil {
			t.Fatalf("query %+v accepted", query)
		}
	}
}

func TestRecomputeWrapsDependencyErrors(t *testing.T) {
	fixture := newFixture(t)
	fixture.policy.err = errors.New("database unavailable")
	if _, err := fixture.service.Recompute(context.Background(), fixture.request, Query{}); err == nil || err.Error() != "read effective policy: database unavailable" {
		t.Fatalf("error = %v", err)
	}
}

type fixture struct {
	request managerapp.RequestContext
	policy  *policyStub
	rarity  *rarityStub
	signals *signalStub
	service *Service
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	tenantID, _ := tenant.NewID("tenant-a")
	request := managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
	policy := &policyStub{value: detection.Policy{CloudRules: []string{"dropped_payload_executed_and_connects"}}}
	rarity := &rarityStub{value: domainidentity.RarityBaseline{WorkloadCounts: map[string]map[string]uint64{
		"global": {"payload_dropped": 1, "suspicious_exec_connect": 1, "dropped_payload_executed_and_connects": 1},
	}}}
	signals := &signalStub{values: []domaintelemetry.Signal{
		{Name: "payload_dropped", BaseRisk: 50, GlobalRarity: 1, Entities: []domaintelemetry.Entity{{Kind: "file", Key: "/tmp/a"}}},
		{Name: "suspicious_exec_connect", BaseRisk: 50, GlobalRarity: 1, Entities: []domaintelemetry.Entity{{Kind: "file", Key: "/tmp/a"}}},
	}}
	return fixture{request: request, policy: policy, rarity: rarity, signals: signals, service: NewService(policy, rarity, signals)}
}

type policyStub struct {
	request managerapp.RequestContext
	value   detection.Policy
	err     error
}

func (stub *policyStub) Effective(_ context.Context, request managerapp.RequestContext, _ domainpolicy.Target) (detection.Policy, error) {
	stub.request = request
	return stub.value, stub.err
}

type rarityStub struct{ value domainidentity.RarityBaseline }

func (stub *rarityStub) Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error) {
	return stub.value, nil
}

type signalStub struct {
	tenantID tenant.ID
	filter   ports.AnalysisSignalFilter
	values   []domaintelemetry.Signal
}

func (stub *signalStub) Signals(_ context.Context, tenantID tenant.ID, filter ports.AnalysisSignalFilter) ([]domaintelemetry.Signal, error) {
	stub.tenantID, stub.filter = tenantID, filter
	return stub.values, nil
}
