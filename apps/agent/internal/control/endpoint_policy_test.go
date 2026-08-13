package control

import (
	"context"
	"errors"
	"testing"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type recordingEndpointPolicyRuntime struct {
	identity           PolicyIdentity
	settings           EndpointPolicySettings
	currentIntent      contract.CollectionIntent
	pending            *PreparedEndpointPolicy
	sensorErr          error
	persistErr         error
	activateManagedErr error
	applyIntents       []contract.CollectionIntent
	saveDesiredCalls   int
	persistCalls       int
	activateCalls      int
	promoteCalls       int
	managedLocks       int
	detectionLocks     int
}

func (r *recordingEndpointPolicyRuntime) PolicyIdentity() PolicyIdentity             { return r.identity }
func (r *recordingEndpointPolicyRuntime) ValidatePolicyContext(RequestContext) error { return nil }
func (r *recordingEndpointPolicyRuntime) BeginLocalPolicyMutation(context.Context, bool) (func(), error) {
	return func() {}, nil
}
func (r *recordingEndpointPolicyRuntime) WithEndpointDetectionUpdate(run func()) {
	r.detectionLocks++
	run()
}
func (r *recordingEndpointPolicyRuntime) WithManagedPolicyTransition(run func()) {
	r.managedLocks++
	run()
}
func (r *recordingEndpointPolicyRuntime) EndpointPolicySettings() EndpointPolicySettings {
	return r.settings
}
func (*recordingEndpointPolicyRuntime) EndpointCollectionContent() agentpolicy.CollectionContentSnapshot {
	return agentpolicy.CollectionContentSnapshot{}
}
func (*recordingEndpointPolicyRuntime) EndpointDetectionContent() detection.ContentSnapshot {
	return detection.ContentSnapshot{Rules: []detection.RuleSpec{{RuleID: "rule-a", RuleSetRef: "ruleset:cep-endpoint"}}}
}
func (r *recordingEndpointPolicyRuntime) CurrentEndpointIntent() contract.CollectionIntent {
	return r.currentIntent
}
func (r *recordingEndpointPolicyRuntime) ApplyEndpointIntent(_ context.Context, intent contract.CollectionIntent) error {
	r.applyIntents = append(r.applyIntents, intent)
	if len(r.applyIntents) == 1 {
		return r.sensorErr
	}
	return nil
}
func (r *recordingEndpointPolicyRuntime) PersistEndpointPolicy(context.Context, PolicySource, agentpolicy.EndpointPolicy) error {
	r.persistCalls++
	return r.persistErr
}
func (r *recordingEndpointPolicyRuntime) SaveDesiredManagedEndpointPolicy(context.Context, agentpolicy.EndpointPolicy) error {
	r.saveDesiredCalls++
	return nil
}
func (r *recordingEndpointPolicyRuntime) ActivateManagedEndpointPolicy(context.Context, agentpolicy.EndpointPolicy) error {
	return r.activateManagedErr
}
func (r *recordingEndpointPolicyRuntime) SetPendingEndpointPolicy(policy PreparedEndpointPolicy) {
	r.pending = &policy
}
func (r *recordingEndpointPolicyRuntime) PendingEndpointPolicy() *PreparedEndpointPolicy {
	return r.pending
}
func (r *recordingEndpointPolicyRuntime) ClearPendingEndpointPolicy() { r.pending = nil }
func (r *recordingEndpointPolicyRuntime) ActivatePreparedEndpointPolicy(PreparedEndpointPolicy) {
	r.activateCalls++
}
func (r *recordingEndpointPolicyRuntime) PromoteManagedAuthority(context.Context) error {
	r.promoteCalls++
	return nil
}
func (*recordingEndpointPolicyRuntime) LoadEndpointPolicy(context.Context, PolicySource) (agentpolicy.EndpointPolicy, bool, error) {
	return agentpolicy.EndpointPolicy{}, false, nil
}
func (*recordingEndpointPolicyRuntime) DesiredManagedEndpointPolicy(context.Context) (localstore.PolicyRecord, localstore.PolicyStatus, bool, error) {
	return localstore.PolicyRecord{}, "", false, nil
}

func TestEndpointPolicyStandalonePersistenceFailureRollsBackSensor(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	runtime.persistErr = errors.New("sqlite commit failed")
	result := NewEndpointPolicyController(runtime).Apply(t.Context(), endpointPolicyCommand(PolicySourceStandalone))

	if result.Status != "rejected" || runtime.persistCalls != 1 || runtime.activateCalls != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
	if len(runtime.applyIntents) != 2 || len(runtime.applyIntents[0].Behaviors) == 0 || len(runtime.applyIntents[1].Behaviors) != 0 {
		t.Fatalf("applied intents=%+v", runtime.applyIntents)
	}
}

func TestEndpointPolicyManagedSensorFailureRemainsPending(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	runtime.sensorErr = errors.New("sensor unavailable")
	result := NewEndpointPolicyController(runtime).Apply(t.Context(), endpointPolicyCommand(PolicySourceManaged))

	if result.Status != "pending" || !result.RequiresRestart || runtime.saveDesiredCalls != 1 || runtime.pending == nil {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
	if runtime.activateCalls != 0 || runtime.promoteCalls != 0 {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestEndpointPolicyManagedDurableActivationFailureRemainsPending(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	runtime.activateManagedErr = errors.New("sqlite activation failed")
	result := NewEndpointPolicyController(runtime).Apply(t.Context(), endpointPolicyCommand(PolicySourceManaged))

	if result.Status != "pending" || runtime.pending == nil || runtime.activateCalls != 0 || runtime.promoteCalls != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestEndpointPolicyManagedActivatesAfterSensorAndStore(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	result := NewEndpointPolicyController(runtime).Apply(t.Context(), endpointPolicyCommand(PolicySourceManaged))

	if result.Status == "rejected" || result.Status == "pending" || runtime.pending != nil {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
	if runtime.saveDesiredCalls != 1 || runtime.activateCalls != 1 || runtime.promoteCalls != 1 || runtime.managedLocks != 2 {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestEndpointPolicyDryRunHasNoSideEffects(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	command := endpointPolicyCommand(PolicySourceManaged)
	command.DryRun = true
	result := NewEndpointPolicyController(runtime).Apply(t.Context(), command)

	if result.Status != "validated" || runtime.saveDesiredCalls != 0 || len(runtime.applyIntents) != 0 || runtime.activateCalls != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestEndpointPolicyRuntimeCapabilitiesAreNotSentToSensor(t *testing.T) {
	runtime := newRecordingEndpointPolicyRuntime()
	runtime.settings.Capabilities = []contract.CollectionBehaviorCapability{{Behavior: "process.exec"}}

	result := NewEndpointPolicyController(runtime).Apply(t.Context(), endpointPolicyCommand(PolicySourceStandalone))

	if result.Status == "rejected" || len(runtime.applyIntents) != 1 {
		t.Fatalf("result=%+v applied intents=%+v", result, runtime.applyIntents)
	}
	if len(runtime.applyIntents[0].Capabilities) != 0 {
		t.Fatalf("sensor capabilities=%+v want none", runtime.applyIntents[0].Capabilities)
	}
}

func newRecordingEndpointPolicyRuntime() *recordingEndpointPolicyRuntime {
	return &recordingEndpointPolicyRuntime{
		identity: PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		settings: EndpointPolicySettings{TenantID: "tenant-a", Telemetry: config.DefaultTelemetryConfig()},
	}
}

func endpointPolicyCommand(source PolicySource) PolicyCommand {
	return PolicyCommand{
		Context:    RequestContext{RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "endpoint", Source: source,
		Document: `{"policy_id":"policy-a","version":2,"collection":{"behaviors":["process.exec"]},"detection":{"rulesets":[{"ref":"ruleset:cep-endpoint"}]},"telemetry":{},"response":{}}`,
	}
}
