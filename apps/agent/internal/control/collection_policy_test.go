package control

import (
	"context"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type recordingCollectionPolicyRuntime struct {
	identity       PolicyIdentity
	active         policymodel.Policy
	current        contract.CollectionIntent
	sensorErr      error
	persistErr     error
	beginMutations []bool
	events         []string
	applied        []contract.CollectionIntent
	activated      int
}

func (r *recordingCollectionPolicyRuntime) PolicyIdentity() PolicyIdentity { return r.identity }
func (*recordingCollectionPolicyRuntime) ValidatePolicyContext(RequestContext) error {
	return nil
}
func (r *recordingCollectionPolicyRuntime) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	r.beginMutations = append(r.beginMutations, mutation)
	return func() {}, nil
}
func (r *recordingCollectionPolicyRuntime) WithCollectionPolicyUpdate(run func()) {
	r.events = append(r.events, "transaction")
	run()
}
func (*recordingCollectionPolicyRuntime) CollectionObserveOnly() bool { return false }
func (*recordingCollectionPolicyRuntime) CollectionDefaultScope() Scope {
	return Scope{Type: "host"}
}
func (*recordingCollectionPolicyRuntime) CollectionContent() agentpolicy.CollectionContentSnapshot {
	return agentpolicy.CollectionContentSnapshot{}
}
func (r *recordingCollectionPolicyRuntime) ActiveCollectionDetectionPolicy() policymodel.Policy {
	return r.active
}
func (*recordingCollectionPolicyRuntime) CollectionCapabilities() []contract.CollectionBehaviorCapability {
	return nil
}
func (*recordingCollectionPolicyRuntime) CollectionDetectionContent() detection.ContentSnapshot {
	return detection.ContentSnapshot{Rules: []detection.RuleSpec{{RuleID: "rule-a", RuleSetRef: "ruleset:cep-endpoint"}}}
}
func (*recordingCollectionPolicyRuntime) CollectionDetectionLimits() detection.EngineLimits {
	return detection.EngineLimits{}
}
func (r *recordingCollectionPolicyRuntime) CurrentCollectionIntent() contract.CollectionIntent {
	return r.current
}
func (r *recordingCollectionPolicyRuntime) ApplyCollectionIntent(_ context.Context, intent contract.CollectionIntent) error {
	r.events = append(r.events, "sensor")
	r.applied = append(r.applied, intent)
	if len(r.applied) == 1 {
		return r.sensorErr
	}
	return nil
}
func (r *recordingCollectionPolicyRuntime) PersistCollectionPolicy(context.Context, agentpolicy.CollectionPolicy) error {
	r.events = append(r.events, "persist")
	return r.persistErr
}
func (r *recordingCollectionPolicyRuntime) ActivateCollectionPolicy(contract.CollectionIntent, *detection.Engine) {
	r.events = append(r.events, "activate")
	r.activated++
}

func TestCollectionPolicyPersistsAfterSensorBeforeActivation(t *testing.T) {
	runtime := newRecordingCollectionPolicyRuntime()

	result := NewCollectionPolicyController(runtime).Apply(t.Context(), collectionPolicyCommand())

	if result.Status == "rejected" || runtime.activated != 1 || len(runtime.events) != 4 || runtime.events[1] != "sensor" || runtime.events[2] != "persist" || runtime.events[3] != "activate" {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestCollectionPolicyPersistenceFailureRollsBackSensor(t *testing.T) {
	runtime := newRecordingCollectionPolicyRuntime()
	runtime.current = contract.CollectionIntent{
		Behaviors:    []string{"file.write"},
		Capabilities: []contract.CollectionBehaviorCapability{{Behavior: "file.write"}},
	}
	runtime.persistErr = errors.New("sqlite commit failed")

	result := NewCollectionPolicyController(runtime).Apply(t.Context(), collectionPolicyCommand())

	if result.Status != "rejected" || runtime.activated != 0 || len(runtime.applied) != 2 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
	if len(runtime.applied[1].Behaviors) != 1 || runtime.applied[1].Behaviors[0] != "file.write" {
		t.Fatalf("rollback intent=%+v", runtime.applied[1])
	}
	if len(runtime.applied[1].Capabilities) != 1 || runtime.applied[1].Capabilities[0].Behavior != "file.write" {
		t.Fatalf("rollback capabilities=%+v", runtime.applied[1].Capabilities)
	}
}

func TestCollectionPolicySensorFailureDoesNotPersist(t *testing.T) {
	runtime := newRecordingCollectionPolicyRuntime()
	runtime.sensorErr = errors.New("sensor unavailable")

	result := NewCollectionPolicyController(runtime).Apply(t.Context(), collectionPolicyCommand())

	if result.Status != "rejected" || runtime.activated != 0 || len(runtime.events) != 2 || runtime.events[1] != "sensor" {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestCollectionPolicyDryRunUsesRequestScopeWithoutSideEffects(t *testing.T) {
	runtime := newRecordingCollectionPolicyRuntime()
	command := collectionPolicyCommand()
	command.DryRun = true
	command.Context.Scope = &Scope{Type: "container", Selector: "container-a"}

	result := NewCollectionPolicyController(runtime).Apply(t.Context(), command)

	if result.Status == "rejected" || len(runtime.applied) != 0 || runtime.activated != 0 || runtime.beginMutations[0] {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func newRecordingCollectionPolicyRuntime() *recordingCollectionPolicyRuntime {
	active := policymodel.DefaultPolicy("tenant-a")
	active.Detection = &policymodel.DetectionPolicy{RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:cep-endpoint"}}}
	return &recordingCollectionPolicyRuntime{
		identity: PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"}, active: active,
	}
}

func collectionPolicyCommand() PolicyCommand {
	return PolicyCommand{
		Context:    RequestContext{RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "collection", Source: PolicySourceStandalone,
		Document: `{"policy_id":"collection-a","version":2,"behaviors":["process.exec"]}`,
	}
}
