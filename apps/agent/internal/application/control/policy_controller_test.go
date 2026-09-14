package control

import (
	"context"
	"strings"
	"testing"
)

type recordingPolicyUseCase struct {
	calls   int
	command PolicyCommand
}

func (r *recordingPolicyUseCase) Apply(_ context.Context, command PolicyCommand) Result {
	r.calls++
	r.command = command
	return Result{Status: "applied", PolicyID: command.PolicyType}
}

type recordingPolicyControllerRuntime struct {
	identity       PolicyIdentity
	snapshot       PolicySnapshot
	beginMutations []bool
}

func (r *recordingPolicyControllerRuntime) PolicyIdentity() PolicyIdentity { return r.identity }
func (*recordingPolicyControllerRuntime) ValidatePolicyContext(RequestContext) error {
	return nil
}
func (r *recordingPolicyControllerRuntime) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	r.beginMutations = append(r.beginMutations, mutation)
	return func() {}, nil
}
func (r *recordingPolicyControllerRuntime) CurrentPolicySnapshot(context.Context) (PolicySnapshot, error) {
	return r.snapshot, nil
}

func TestPolicyControllerRoutesManagedSourceToManagedEndpoint(t *testing.T) {
	controller, cases, _ := newRecordingPolicyController()

	result := controller.ApplyPolicy(t.Context(), PolicyCommand{PolicyType: "telemetry", Source: PolicySourceManaged})

	if result.Status != "applied" || cases.ManagedEndpoint.(*recordingPolicyUseCase).calls != 1 || cases.ManagedEndpoint.(*recordingPolicyUseCase).command.PolicyType != "endpoint" {
		t.Fatalf("result=%+v managed=%+v", result, cases.ManagedEndpoint)
	}
}

func TestPolicyControllerDefaultsStandaloneToEndpoint(t *testing.T) {
	controller, cases, _ := newRecordingPolicyController()

	controller.ApplyPolicy(t.Context(), PolicyCommand{Source: PolicySourceStandalone})

	if cases.StandaloneEndpoint.(*recordingPolicyUseCase).calls != 1 {
		t.Fatalf("standalone=%+v", cases.StandaloneEndpoint)
	}
}

func TestPolicyControllerRoutesStandalonePolicyTypes(t *testing.T) {
	controller, cases, _ := newRecordingPolicyController()

	for _, policyType := range []string{"collection", "detection", "telemetry"} {
		result := controller.ApplyPolicy(t.Context(), PolicyCommand{PolicyType: policyType, Source: PolicySourceStandalone})
		if result.PolicyID != policyType {
			t.Fatalf("type=%s result=%+v", policyType, result)
		}
	}
	if cases.Collection.(*recordingPolicyUseCase).calls != 1 || cases.Detection.(*recordingPolicyUseCase).calls != 1 || cases.Telemetry.(*recordingPolicyUseCase).calls != 1 {
		t.Fatalf("cases=%+v", cases)
	}
}

func TestPolicyControllerUnsupportedTypeChecksAuthority(t *testing.T) {
	controller, _, runtime := newRecordingPolicyController()

	result := controller.ApplyPolicy(t.Context(), PolicyCommand{PolicyType: "unknown", Source: PolicySourceStandalone})

	if result.Status != "rejected" || !strings.Contains(result.Message, `unsupported policy type "unknown"`) || len(runtime.beginMutations) != 1 || !runtime.beginMutations[0] {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestCurrentPolicyUsesEndpointDocumentAndPendingProjection(t *testing.T) {
	controller, _, runtime := newRecordingPolicyController()
	runtime.snapshot = PolicySnapshot{PolicyID: "endpoint-a", Version: 7, RawJSON: `{"policy_id":"endpoint-a"}`, Pending: &PendingPolicy{PolicyID: "endpoint-b", Version: 8, Status: "pending", Source: PolicySourceManaged, Digest: "sha256:pending"}}

	snapshot, err := controller.CurrentPolicy(t.Context())

	if err != nil || snapshot.PolicyID != "endpoint-a" || snapshot.Version != 7 || !strings.Contains(snapshot.RawJSON, `"policy_id":"endpoint-a"`) {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if snapshot.Pending == nil || snapshot.Pending.PolicyID != "endpoint-b" || snapshot.Pending.Digest != "sha256:pending" {
		t.Fatalf("pending=%+v", snapshot.Pending)
	}
}

func newRecordingPolicyController() (*ApplicationPolicyController, PolicyUseCases, *recordingPolicyControllerRuntime) {
	runtime := &recordingPolicyControllerRuntime{identity: PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	cases := PolicyUseCases{
		StandaloneEndpoint: &recordingPolicyUseCase{}, ManagedEndpoint: &recordingPolicyUseCase{},
		Collection: &recordingPolicyUseCase{}, Detection: &recordingPolicyUseCase{}, Telemetry: &recordingPolicyUseCase{},
	}
	return NewApplicationPolicyController(runtime, cases), cases, runtime
}
