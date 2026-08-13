package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type recordingTelemetryPolicyRuntime struct {
	identity       PolicyIdentity
	baseline       config.TelemetryConfig
	persistErr     error
	beginMutations []bool
	events         []string
	persisted      policymodel.TelemetryPolicy
	activated      config.EffectiveTelemetry
}

func (r *recordingTelemetryPolicyRuntime) PolicyIdentity() PolicyIdentity { return r.identity }
func (*recordingTelemetryPolicyRuntime) ValidatePolicyContext(RequestContext) error {
	return nil
}
func (r *recordingTelemetryPolicyRuntime) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	r.beginMutations = append(r.beginMutations, mutation)
	return func() {}, nil
}
func (r *recordingTelemetryPolicyRuntime) TelemetryPolicyBaseline() config.TelemetryConfig {
	return r.baseline
}
func (r *recordingTelemetryPolicyRuntime) PersistTelemetryPolicy(_ context.Context, policy policymodel.TelemetryPolicy) error {
	r.events = append(r.events, "persist")
	r.persisted = policy
	return r.persistErr
}
func (r *recordingTelemetryPolicyRuntime) ActivateTelemetryPolicy(effective config.EffectiveTelemetry) {
	r.events = append(r.events, "activate")
	r.activated = effective
}

func TestTelemetryPolicyPersistsBeforeActivation(t *testing.T) {
	runtime := newRecordingTelemetryPolicyRuntime()
	command := telemetryPolicyCommand()

	result := NewTelemetryPolicyController(runtime).Apply(t.Context(), command)

	if result.Status != "applied" || len(runtime.events) != 2 || runtime.events[0] != "persist" || runtime.events[1] != "activate" {
		t.Fatalf("result=%+v events=%v", result, runtime.events)
	}
	if runtime.activated.MaxBatchItems != 64 || runtime.activated.MaxBatchBytes != 128<<10 || runtime.activated.FlushInterval != 2*time.Second {
		t.Fatalf("activated=%+v", runtime.activated)
	}
}

func TestTelemetryPolicyPersistenceFailureDoesNotActivate(t *testing.T) {
	runtime := newRecordingTelemetryPolicyRuntime()
	runtime.persistErr = errors.New("sqlite commit failed")

	result := NewTelemetryPolicyController(runtime).Apply(t.Context(), telemetryPolicyCommand())

	if result.Status != "rejected" || len(runtime.events) != 1 || runtime.events[0] != "persist" {
		t.Fatalf("result=%+v events=%v", result, runtime.events)
	}
}

func TestTelemetryPolicyDryRunHasNoSideEffects(t *testing.T) {
	runtime := newRecordingTelemetryPolicyRuntime()
	command := telemetryPolicyCommand()
	command.DryRun = true

	result := NewTelemetryPolicyController(runtime).Apply(t.Context(), command)

	if result.Status != "validated" || len(runtime.events) != 0 || len(runtime.beginMutations) != 1 || runtime.beginMutations[0] {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestTelemetryPolicyAcceptsNestedDocument(t *testing.T) {
	runtime := newRecordingTelemetryPolicyRuntime()
	command := telemetryPolicyCommand()
	command.Document = `{"telemetry":{"max_batch_items":32,"max_batch_bytes":65536,"flush_interval":"1s"}}`
	command.Telemetry = nil

	result := NewTelemetryPolicyController(runtime).Apply(t.Context(), command)

	if result.Status != "applied" || runtime.persisted.MaxBatchItems != 32 || runtime.persisted.MaxBatchBytes != 65536 || runtime.persisted.FlushInterval != "1s" {
		t.Fatalf("result=%+v persisted=%+v", result, runtime.persisted)
	}
}

func newRecordingTelemetryPolicyRuntime() *recordingTelemetryPolicyRuntime {
	return &recordingTelemetryPolicyRuntime{
		identity: PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		baseline: config.DefaultTelemetryConfig(),
	}
}

func telemetryPolicyCommand() PolicyCommand {
	return PolicyCommand{
		Context:    RequestContext{RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "telemetry", Source: PolicySourceStandalone,
		Telemetry: &TelemetryPolicy{MaxBatchItems: 64, MaxBatchBytes: 128 << 10, FlushInterval: "2s"},
	}
}
