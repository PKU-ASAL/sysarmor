package control

import (
	"context"
	"testing"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type telemetryApplicationFake struct {
	validated, activated, mutation bool
	input                          *applicationpolicy.TelemetryInput
	candidate                      applicationpolicy.TelemetryCandidate
}

func (*telemetryApplicationFake) PolicyIdentity() PolicyIdentity {
	return PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"}
}
func (*telemetryApplicationFake) ValidatePolicyContext(RequestContext) error { return nil }
func (f *telemetryApplicationFake) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	f.mutation = mutation
	return func() {}, nil
}
func (f *telemetryApplicationFake) ValidateTelemetry(_ context.Context, _ string, input *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error) {
	f.validated = true
	f.input = input
	return f.candidate, nil
}
func (f *telemetryApplicationFake) ActivateTelemetry(_ context.Context, _ string, input *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error) {
	f.activated = true
	f.input = input
	return f.candidate, nil
}

type controlTelemetryCandidate struct{}

func (controlTelemetryCandidate) ReportJSON() string { return `{"telemetry":{}}` }

func TestTelemetryControlDelegatesStructuredInput(t *testing.T) {
	application := &telemetryApplicationFake{candidate: controlTelemetryCandidate{}}
	result := NewTelemetryPolicyController(application).Apply(t.Context(), PolicyCommand{Telemetry: &TelemetryPolicy{MaxBatchItems: 64}})
	if !application.activated || !application.mutation || application.input.MaxBatchItems != 64 || result.Status != "applied" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}
func TestTelemetryControlDryRunOnlyValidates(t *testing.T) {
	application := &telemetryApplicationFake{candidate: controlTelemetryCandidate{}}
	result := NewTelemetryPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", DryRun: true})
	if !application.validated || application.activated || application.mutation || result.Status != "validated" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}
