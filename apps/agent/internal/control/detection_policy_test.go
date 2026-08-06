package control

import (
	"context"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type recordingDetectionPolicyRuntime struct {
	identity       PolicyIdentity
	active         policymodel.Policy
	persistErr     error
	beginMutations []bool
	events         []string
	transactions   int
	rejected       int
	activated      int
}

func (r *recordingDetectionPolicyRuntime) PolicyIdentity() PolicyIdentity { return r.identity }
func (*recordingDetectionPolicyRuntime) ValidatePolicyContext(RequestContext) error {
	return nil
}
func (r *recordingDetectionPolicyRuntime) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	r.beginMutations = append(r.beginMutations, mutation)
	return func() {}, nil
}
func (r *recordingDetectionPolicyRuntime) WithDetectionPolicyUpdate(run func()) {
	r.transactions++
	r.events = append(r.events, "transaction")
	run()
}
func (r *recordingDetectionPolicyRuntime) ActiveDetectionPolicy() policymodel.Policy {
	return r.active
}
func (*recordingDetectionPolicyRuntime) DetectionCollectionIntent() contract.CollectionIntent {
	return contract.CollectionIntent{}
}
func (*recordingDetectionPolicyRuntime) DetectionContent() detection.ContentSnapshot {
	return detection.ContentSnapshot{Rules: []detection.RuleSpec{{RuleID: "rule-a", RuleSetRef: "ruleset:cep-endpoint"}}}
}
func (*recordingDetectionPolicyRuntime) DetectionLimits() detection.EngineLimits {
	return detection.EngineLimits{}
}
func (r *recordingDetectionPolicyRuntime) PersistDetectionPolicy(context.Context, policymodel.DetectionPolicy) error {
	r.events = append(r.events, "persist")
	return r.persistErr
}
func (r *recordingDetectionPolicyRuntime) RecordRejectedDetection(policymodel.Policy, detection.ApplyReport) {
	r.events = append(r.events, "reject")
	r.rejected++
}
func (r *recordingDetectionPolicyRuntime) ActivateDetectionPolicy(policymodel.Policy, *detection.Engine, detection.ApplyReport) {
	r.events = append(r.events, "activate")
	r.activated++
}

func TestDetectionPolicyPersistsBeforeActivation(t *testing.T) {
	runtime := newRecordingDetectionPolicyRuntime()

	result := NewDetectionPolicyController(runtime).Apply(t.Context(), detectionPolicyCommand())

	if result.Status == "rejected" || runtime.activated != 1 || len(runtime.events) != 3 || runtime.events[1] != "persist" || runtime.events[2] != "activate" {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestDetectionPolicyPersistenceFailureDoesNotActivate(t *testing.T) {
	runtime := newRecordingDetectionPolicyRuntime()
	runtime.persistErr = errors.New("sqlite commit failed")

	result := NewDetectionPolicyController(runtime).Apply(t.Context(), detectionPolicyCommand())

	if result.Status != "rejected" || runtime.activated != 0 || len(runtime.events) != 2 || runtime.events[1] != "persist" {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestDetectionPolicyRejectedBuildOnlyRecordsStatus(t *testing.T) {
	runtime := newRecordingDetectionPolicyRuntime()
	command := detectionPolicyCommand()
	command.Document = `{"rulesets":[{"ref":"ruleset:missing"}]}`

	result := NewDetectionPolicyController(runtime).Apply(t.Context(), command)

	if result.Status != "rejected" || runtime.rejected != 1 || runtime.activated != 0 || len(runtime.events) != 2 || runtime.events[1] != "reject" {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestDetectionPolicyDryRunHasNoSideEffects(t *testing.T) {
	runtime := newRecordingDetectionPolicyRuntime()
	command := detectionPolicyCommand()
	command.DryRun = true

	result := NewDetectionPolicyController(runtime).Apply(t.Context(), command)

	if result.Status == "rejected" || runtime.rejected != 0 || runtime.activated != 0 || len(runtime.events) != 1 || runtime.beginMutations[0] {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func newRecordingDetectionPolicyRuntime() *recordingDetectionPolicyRuntime {
	return &recordingDetectionPolicyRuntime{
		identity: PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		active:   policymodel.DefaultPolicy("tenant-a"),
	}
}

func detectionPolicyCommand() PolicyCommand {
	return PolicyCommand{
		Context:    RequestContext{RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a"},
		PolicyType: "detection", Source: PolicySourceStandalone,
		Document: `{"policy_id":"detection-a","version":2,"mode":"observe","rulesets":[{"ref":"ruleset:cep-endpoint"}]}`,
	}
}
