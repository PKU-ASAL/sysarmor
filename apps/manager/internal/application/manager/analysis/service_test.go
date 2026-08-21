package analysis

import (
	"context"
	"errors"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestRecomputeUsesAuthenticatedTenantAndAnalysisPolicy(t *testing.T) {
	fixture := newFixture(t)
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture.service.now = func() time.Time { return now }
	result, err := fixture.service.Recompute(context.Background(), fixture.request, Query{
		Target: domainpolicy.Target{AgentID: "agent-a"}, Labels: map[string]string{"scenario": "one"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.telemetry.signalTenantID != fixture.request.Actor.TenantID || fixture.telemetry.eventTenantID != fixture.request.Actor.TenantID || fixture.policy.request.Actor.TenantID != fixture.request.Actor.TenantID {
		t.Fatalf("policy tenant = %q, signal tenant = %q, event tenant = %q", fixture.policy.request.Actor.TenantID, fixture.telemetry.signalTenantID, fixture.telemetry.eventTenantID)
	}
	if fixture.telemetry.signalFilter.Labels["scenario"] != "one" || fixture.telemetry.signalFilter.Where != domaintelemetry.SignalWhereEndpoint || fixture.telemetry.eventFilter.Labels["scenario"] != "one" {
		t.Fatalf("signal filter = %+v, event filter = %+v", fixture.telemetry.signalFilter, fixture.telemetry.eventFilter)
	}
	if fixture.telemetry.eventFilter.AgentID != "agent-a" || fixture.telemetry.signalFilter.AgentID != "agent-a" ||
		!fixture.telemetry.eventFilter.From.Equal(now.Add(-15*time.Minute)) || !fixture.telemetry.eventFilter.To.Equal(now) ||
		!fixture.telemetry.signalFilter.From.Equal(now.Add(-15*time.Minute)) || !fixture.telemetry.signalFilter.To.Equal(now) {
		t.Fatalf("event filter = %+v, signal filter = %+v", fixture.telemetry.eventFilter, fixture.telemetry.signalFilter)
	}
	if len(result.Incidents) != 1 || result.Incidents[0].Converge.Score != 90 {
		t.Fatalf("analysis = %+v", result)
	}
	if evidence := result.Incidents[0].Evidence; evidence == nil || len(evidence.Edges) != 1 || evidence.Edges[0].EventRefs[0] != "event-write" {
		t.Fatalf("evidence = %+v", result.Incidents[0].Evidence)
	}
}

func TestRecomputeRequiresAgentTarget(t *testing.T) {
	fixture := newFixture(t)
	_, err := fixture.service.Recompute(context.Background(), fixture.request, Query{})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("failure kind = %v, error = %v", failure.KindOf(err), err)
	}
}

func TestRecomputeCanDisableCrossLineage(t *testing.T) {
	fixture := newFixture(t)
	result, err := fixture.service.Recompute(context.Background(), fixture.request, Query{Target: domainpolicy.Target{AgentID: "agent-a"}, Disable: "cloud.cross_lineage"})
	if err != nil || len(result.Incidents) != 0 {
		t.Fatalf("analysis = %+v, error = %v", result, err)
	}
}

func TestRecomputeRejectsUnknownControls(t *testing.T) {
	fixture := newFixture(t)
	for _, query := range []Query{{Target: domainpolicy.Target{AgentID: "agent-a"}, Disable: "unknown"}, {Target: domainpolicy.Target{AgentID: "agent-a"}, Mode: "unknown"}} {
		if _, err := fixture.service.Recompute(context.Background(), fixture.request, query); err == nil {
			t.Fatalf("query %+v accepted", query)
		}
	}
}

func TestRecomputeWrapsDependencyErrors(t *testing.T) {
	fixture := newFixture(t)
	fixture.policy.err = errors.New("database unavailable")
	if _, err := fixture.service.Recompute(context.Background(), fixture.request, Query{Target: domainpolicy.Target{AgentID: "agent-a"}}); err == nil || err.Error() != "read effective policy: database unavailable" {
		t.Fatalf("error = %v", err)
	}
}

type fixture struct {
	request   managerapp.RequestContext
	policy    *policyStub
	rarity    *rarityStub
	telemetry *telemetryStub
	service   *Service
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	tenantID, _ := tenant.NewID("tenant-a")
	request := managerapp.RequestContext{Actor: tenant.Actor{Subject: "viewer-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer)}}
	policy := &policyStub{value: detection.Policy{CloudRules: []string{"dropped_payload_executed_and_connects"}}}
	rarity := &rarityStub{value: domainidentity.RarityBaseline{WorkloadCounts: map[string]map[string]uint64{
		"global": {"payload_dropped": 1, "suspicious_exec_connect": 1, "dropped_payload_executed_and_connects": 1},
	}}}
	telemetry := &telemetryStub{events: []domaintelemetry.Event{{
		ID: "event-write", Behavior: "file.write", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "process-a"},
		Object: &domaintelemetry.ObjectRef{Kind: "file", FilePath: "/tmp/a"}, Labels: map[string]string{"scenario": "one"},
	}}, signals: []domaintelemetry.Signal{
		{Name: "payload_dropped", BaseRisk: 50, GlobalRarity: 1, Entities: []domaintelemetry.Entity{{Kind: "file", Key: "/tmp/a"}}},
		{Name: "suspicious_exec_connect", BaseRisk: 50, GlobalRarity: 1, Entities: []domaintelemetry.Entity{{Kind: "file", Key: "/tmp/a"}}},
	}}
	return fixture{request: request, policy: policy, rarity: rarity, telemetry: telemetry, service: NewService(policy, rarity, telemetry)}
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

type telemetryStub struct {
	eventTenantID, signalTenantID tenant.ID
	eventFilter                   ports.AnalysisEventFilter
	signalFilter                  ports.AnalysisSignalFilter
	events                        []domaintelemetry.Event
	signals                       []domaintelemetry.Signal
}

func (stub *telemetryStub) Events(_ context.Context, tenantID tenant.ID, filter ports.AnalysisEventFilter) ([]domaintelemetry.Event, error) {
	stub.eventTenantID, stub.eventFilter = tenantID, filter
	return stub.events, nil
}

func (stub *telemetryStub) Signals(_ context.Context, tenantID tenant.ID, filter ports.AnalysisSignalFilter) ([]domaintelemetry.Signal, error) {
	stub.signalTenantID, stub.signalFilter = tenantID, filter
	return stub.signals, nil
}
