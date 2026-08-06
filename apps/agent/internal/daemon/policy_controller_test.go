package daemon

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func TestApplyPolicyRequestPreservesScopeAndStructuredTelemetry(t *testing.T) {
	req := applyPolicyRequest(agentcontrol.PolicyCommand{
		Context: agentcontrol.RequestContext{
			RequestID: "request-a", Scope: &agentcontrol.Scope{Type: "container", Selector: "container-a"},
		},
		PolicyType: "telemetry",
		Telemetry:  &agentcontrol.TelemetryPolicy{MaxBatchItems: 64, MaxBatchBytes: 65536, FlushInterval: "2s"},
	})
	if req.GetContext().GetScope().GetType() != "container" || req.GetContext().GetScope().GetSelector() != "container-a" ||
		req.GetTelemetry().GetMaxBatchItems() != 64 || req.GetTelemetry().GetMaxBatchBytes() != 65536 || req.GetTelemetry().GetFlushInterval() != "2s" {
		t.Fatalf("request=%+v", req)
	}
}

func TestControlResultPreservesProtocolFields(t *testing.T) {
	want := &controlplanev1.ControlAck{
		RequestId: "request-a", TenantId: "tenant-a", AgentId: "agent-a",
		Status: "degraded", Message: "applied with warnings", PolicyId: "policy-a", PolicyVersion: 7,
		Details: []string{"warning-a"}, ReportJson: `{"status":"degraded"}`,
		Sections: []*controlplanev1.AppliedSection{{
			Name: "collection", Status: "applied", Message: "updated",
			RequiresRestart: true, Details: []string{"section-warning"}, ReportJson: `{"backend":"tetragon"}`,
		}},
	}

	got := controlResult(want)
	if got.RequestID != want.GetRequestId() || got.TenantID != want.GetTenantId() || got.AgentID != want.GetAgentId() ||
		got.Status != want.GetStatus() || got.Message != want.GetMessage() || got.PolicyID != want.GetPolicyId() ||
		got.Version != want.GetPolicyVersion() || got.ReportJSON != want.GetReportJson() || len(got.Details) != 1 ||
		len(got.Sections) != 1 || !got.RequiresRestart || len(got.Sections[0].Details) != 1 ||
		got.Sections[0].Details[0] != "section-warning" || got.Sections[0].ReportJSON != want.GetSections()[0].GetReportJson() {
		t.Fatalf("controlResult()=%+v want=%+v", got, want)
	}
}

func TestStandaloneTelemetryWithoutStoreDoesNotMutateEndpointPolicy(t *testing.T) {
	runner := &AgentRuntime{Config: config.Config{
		Agent: config.AgentConfig{ID: "agent-a", TenantID: "tenant-a"}, Telemetry: config.DefaultTelemetryConfig(),
	}}
	runner.setEndpointPolicy(agentpolicy.EndpointPolicy{PolicyID: "endpoint-a", Version: 7})
	controller := newPolicyController(runner, nil, nil)

	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		Context:    agentcontrol.RequestContext{TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "telemetry", Source: agentcontrol.PolicySourceStandalone,
		Telemetry: &agentcontrol.TelemetryPolicy{MaxBatchItems: 64, MaxBatchBytes: 128 << 10, FlushInterval: "2s"},
	})

	if result.Status != "applied" {
		t.Fatalf("result=%+v", result)
	}
	if endpoint := runner.currentEndpointPolicy(); endpoint.PolicyID != "endpoint-a" || endpoint.Version != 7 {
		t.Fatalf("endpoint=%+v", endpoint)
	}
	if effective := runner.currentEffectiveTelemetry(); effective.MaxBatchItems != 64 || effective.FlushInterval != 2*time.Second {
		t.Fatalf("effective=%+v", effective)
	}
}
