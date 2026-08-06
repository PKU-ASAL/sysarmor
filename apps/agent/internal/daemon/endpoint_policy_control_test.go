package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

const standaloneEndpointPolicyJSON = `{"policy_id":"standalone","version":1,"collection":{"behaviors":["process.exec"]},"detection":{"rulesets":[{"ref":"ruleset:cep-endpoint"}]},"telemetry":{},"response":{}}`

func TestManagerDefaultEndpointPolicyPassesStrictPreparation(t *testing.T) {
	policy := policymodel.ManagerDefaultPolicy("default")
	document, err := json.Marshal(policy.EndpointPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, nil, &healthOnlySensor{})
	prepared, err := newPolicyController(runner, nil, nil).prepareEndpointPolicy(string(document))
	if err != nil {
		t.Fatalf("prepare manager default endpoint policy: %v", err)
	}
	if len(prepared.Endpoint.Detection.RuleSets) != 1 || prepared.Endpoint.Detection.RuleSets[0].Ref != "ruleset:cep-endpoint" {
		t.Fatalf("manager default rulesets = %+v", prepared.Endpoint.Detection.RuleSets)
	}
}

func TestManagerEndpointPolicyPreservesStandaloneSlot(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	server := newPolicyController(runner, sensorruntime.New(runner.Sensor), nil)
	ack := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	if ack.GetStatus() == "rejected" {
		t.Fatalf("manager policy ack=%+v", ack)
	}
	preserved, ok, err := store.PolicySlot(t.Context(), "endpoint", localstore.PolicySourceStandalone)
	if err != nil || !ok || preserved.Version != 1 {
		t.Fatalf("standalone slot=%+v ok=%t err=%v", preserved, ok, err)
	}
	active, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != localstore.PolicySourceManaged || active.Version != 5 {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, err)
	}
}

func TestRestoreStandaloneEndpointPolicyCannotBypassManagedAuthority(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	managed := standalone
	managed.PolicyID = "managed"
	managed.Version = 5
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.ActivateManagedEndpointPolicy(t.Context(), store, managed); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	runner.setEndpointPolicy(managed)
	server := newPolicyController(runner, sensorruntime.New(runner.Sensor), nil)
	if err := server.restoreStandaloneEndpointPolicy(t.Context()); err == nil {
		t.Fatal("managed enrollment restored standalone policy without revocation")
	}
	_, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != localstore.PolicySourceManaged || runner.currentEndpointPolicy().PolicyID != "managed" {
		t.Fatalf("source=%q ok=%t policy=%+v err=%v", source, ok, runner.currentEndpointPolicy(), err)
	}
}

func TestManagerPolicyPromotesEnrollingAgentToManaged(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", TenantID: "local"})
	server := newPolicyController(runner, sensorruntime.New(runner.Sensor), nil)
	ack := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	got, err := store.Enrollment(t.Context())
	if err != nil || ack.GetStatus() == "rejected" || got.State != localstore.StateManaged || runner.currentIdentity().AgentID != "agent-a" {
		t.Fatalf("ack=%+v enrollment=%+v identity=%+v err=%v", ack, got, runner.currentIdentity(), err)
	}
}

func TestApplyAndActivateIntentReportsRollbackFailure(t *testing.T) {
	previous := contract.CollectionIntent{Behaviors: []string{"process.exec"}}
	next := contract.CollectionIntent{Behaviors: []string{"file.write"}}
	applyCalls := 0
	err := agentcontrol.ApplyAndActivateEndpointIntent(t.Context(), previous, next, func(_ context.Context, intent contract.CollectionIntent) error {
		applyCalls++
		if applyCalls == 2 && len(intent.Behaviors) == 1 && intent.Behaviors[0] == "process.exec" {
			return errors.New("rollback failed")
		}
		return nil
	}, func(context.Context) error {
		return errors.New("activation failed")
	})
	if err == nil || !strings.Contains(err.Error(), "activation failed") || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("applyAndActivateIntent() error = %v", err)
	}
}

func TestManagerPolicyPersistsPendingWhenSensorUnavailable(t *testing.T) {
	store, _, server := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	ack := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	desired, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", localstore.PolicySourceManaged)
	active, source, activeOK, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	enrollment, enrollmentErr := store.Enrollment(t.Context())
	if ack.GetStatus() != "pending" || err != nil || !ok || status != localstore.PolicyStatusPending || desired.Version != 5 {
		t.Fatalf("ack=%+v desired=%+v status=%q ok=%t err=%v", ack, desired, status, ok, err)
	}
	if activeErr != nil || !activeOK || source != localstore.PolicySourceStandalone || active.Version != 1 || enrollmentErr != nil || enrollment.State != localstore.StateEnrolling {
		t.Fatalf("active=%+v source=%q ok=%t enrollment=%+v errors=%v/%v", active, source, activeOK, enrollment, activeErr, enrollmentErr)
	}
}

func TestCurrentPolicyReportsPendingManagedPolicy(t *testing.T) {
	store, _, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	ack := controller.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	if ack.GetStatus() != "pending" {
		t.Fatalf("ack=%+v", ack)
	}
	current, err := controller.CurrentPolicy(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	pending := current.Pending
	if current.PolicyID != "standalone" || current.Version != 1 || pending == nil || pending.Status != "pending" || pending.Source != agentcontrol.PolicySourceManaged || pending.PolicyID != "managed" || pending.Version != 5 || pending.Digest == "" {
		t.Fatalf("current=%+v pending=%+v", current, pending)
	}
}

func TestHealthReportsPendingManagedPolicy(t *testing.T) {
	store, runner, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	ack := controller.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	if ack.GetStatus() != "pending" {
		t.Fatalf("ack=%+v", ack)
	}
	server := &localStatusService{runner: runner, runtime: controller.runtime}
	health, err := server.Health(t.Context(), &controlplanev1.HealthRequest{})
	if err != nil {
		t.Fatal(err)
	}
	pending := health.GetPendingPolicy()
	if health.GetStatus() != "degraded" || pending.GetStatus() != "pending" || pending.GetSource() != "managed" || pending.GetPolicyId() != "managed" || pending.GetVersion() != 5 || pending.GetDigest() == "" {
		t.Fatalf("health=%+v pending=%+v", health, pending)
	}
}

func TestPendingManagerPolicyBecomesAppliedAfterSensorRecovery(t *testing.T) {
	store, runner, server := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", TenantID: "local"})
	ack := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed", 5), localstore.PolicySourceManaged)
	if ack.GetStatus() != "pending" || runner.pendingEndpoint == nil {
		t.Fatalf("pending ack=%+v pending=%+v", ack, runner.pendingEndpoint)
	}
	if err := runner.completePendingEndpointPolicy(t.Context(), runner.pendingEndpoint.Intent); err != nil {
		t.Fatal(err)
	}
	_, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", localstore.PolicySourceManaged)
	active, source, activeOK, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	enrollment, enrollmentErr := store.Enrollment(t.Context())
	if err != nil || ok || status != "" || activeErr != nil || !activeOK || source != localstore.PolicySourceManaged || active.Version != 5 {
		t.Fatalf("status=%q ok=%t active=%+v source=%q activeOK=%t errors=%v/%v", status, ok, active, source, activeOK, err, activeErr)
	}
	if enrollmentErr != nil || enrollment.State != localstore.StateManaged || runner.currentEndpointPolicy().PolicyID != "managed" || runner.currentIdentity().AgentID != "agent-a" {
		t.Fatalf("enrollment=%+v policy=%+v identity=%+v err=%v", enrollment, runner.currentEndpointPolicy(), runner.currentIdentity(), enrollmentErr)
	}
}

func TestManagedEndpointPolicyDoesNotReconfigureTelemetryBatcher(t *testing.T) {
	store, runner, pendingController := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	sensor := runner.Sensor.(*applyErrorSensor)
	sensor.err = nil
	batcher := telemetry.NewBatcher(nil, 10, time.Hour, 2, 12345)
	controller := newPolicyController(runner, pendingController.runtime, batcher)
	request := managedPolicyRequest("managed", 5)

	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		Document: request.GetPolicyJson(), PolicyType: "endpoint", Source: agentcontrol.PolicySourceManaged,
	})

	if result.Status == "rejected" || result.Status == "pending" {
		t.Fatalf("result=%+v", result)
	}
	if got := batcher.Stats().MaxBytes; got != 12345 {
		t.Fatalf("batch max bytes=%d want 12345", got)
	}
}

func TestSuccessfulManagerPolicySupersedesOlderPendingPolicy(t *testing.T) {
	store, runner, server := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	sensor := runner.Sensor.(*applyErrorSensor)
	first := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed-old", 5), localstore.PolicySourceManaged)
	if first.GetStatus() != "pending" || runner.pendingEndpoint == nil {
		t.Fatalf("first ack=%+v pending=%+v", first, runner.pendingEndpoint)
	}
	sensor.err = nil
	second := server.applyEndpointPolicyInternal(t.Context(), managedPolicyRequest("managed-new", 6), localstore.PolicySourceManaged)
	_, _, pending, pendingErr := store.DesiredPolicy(t.Context(), "endpoint", localstore.PolicySourceManaged)
	active, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if second.GetStatus() == "rejected" || runner.pendingEndpoint != nil || pending || pendingErr != nil {
		t.Fatalf("second ack=%+v pending=%+v storedPending=%t err=%v", second, runner.pendingEndpoint, pending, pendingErr)
	}
	if activeErr != nil || !ok || source != localstore.PolicySourceManaged || active.Version != 6 {
		t.Fatalf("active=%+v source=%q ok=%t err=%v", active, source, ok, activeErr)
	}
}

func TestRestorePendingManagerPolicyAfterRestart(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	managed := standalone
	managed.PolicyID = "managed"
	managed.Version = 5
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveDesiredManagedEndpointPolicy(t.Context(), store, managed); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, nil)
	server := newPolicyController(runner, nil, nil)
	prepared, ok, err := server.loadPendingManagedEndpointPolicy(t.Context())
	if err != nil || !ok || prepared.Endpoint.PolicyID != "managed" || len(prepared.Intent.Behaviors) != 1 {
		t.Fatalf("prepared=%+v ok=%t err=%v", prepared, ok, err)
	}
}

func TestDuplicateManagedPolicyDoesNotDeadlockStartupPendingActivation(t *testing.T) {
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	server := newPolicyController(runner, nil, nil)
	request := managedPolicyRequest("managed", 5)
	pending, err := server.prepareEndpointPolicy(request.GetPolicyJson())
	if err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveDesiredManagedEndpointPolicy(t.Context(), store, pending.Endpoint); err != nil {
		t.Fatal(err)
	}
	runner.setPendingEndpointPolicy(pending)
	manager := sensorruntime.New(runner.Sensor)
	supervisor := sensorruntime.NewSubscriptionSupervisor(sensorruntime.AdaptManager(manager), pending.Intent, sensorruntime.RetryOptions{})
	runner.setSensorSupervisor(supervisor)
	callbackReady := make(chan struct{})
	allowCallback := make(chan struct{})
	supervisor.OnApplied(func(ctx context.Context, intent contract.CollectionIntent) error {
		close(callbackReady)
		<-allowCallback
		return runner.completePendingEndpointPolicy(ctx, intent)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)
	<-callbackReady
	done := make(chan *controlplanev1.ControlAck, 1)
	go func() { done <- server.applyEndpointPolicyInternal(ctx, request, localstore.PolicySourceManaged) }()
	deadline := time.Now().Add(time.Second)
	for runner.policyAuthorityMu.TryLock() {
		runner.policyAuthorityMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("duplicate policy handler did not enter managed transition")
		}
		time.Sleep(time.Millisecond)
	}
	close(allowCallback)
	select {
	case ack := <-done:
		if ack.GetStatus() == "rejected" {
			t.Fatalf("duplicate policy ack=%+v", ack)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("duplicate managed policy deadlocked startup pending activation")
	}
}

func (s *policyController) endpointPolicyControl() *agentcontrol.EndpointPolicyController {
	return agentcontrol.NewEndpointPolicyController(newEndpointPolicyRuntime(s.runner, s.runtime, s.batcher))
}

func (s *policyController) prepareEndpointPolicy(document string) (agentcontrol.PreparedEndpointPolicy, error) {
	return s.endpointPolicyControl().Prepare(document)
}

func (s *policyController) applyEndpointPolicyInternal(ctx context.Context, req *controlplanev1.ApplyPolicyRequest, source localstore.PolicySource) *controlplanev1.ControlAck {
	command := agentcontrol.PolicyCommand{
		Context: agentcontrol.RequestContext{
			RequestID: req.GetContext().GetRequestId(), TenantID: req.GetContext().GetTenantId(), AgentID: req.GetContext().GetAgentId(),
		},
		PolicyType: "endpoint", Document: req.GetPolicyJson(), DryRun: req.GetDryRun(), Source: agentcontrol.PolicySource(source),
	}
	return policyResultAck(s.endpointPolicyControl().Apply(ctx, command))
}

func (s *policyController) restoreStandaloneEndpointPolicy(ctx context.Context) error {
	return s.endpointPolicyControl().RestoreStandalone(ctx, func(ctx context.Context) error {
		return s.runner.localStore.ActivateStandalonePolicy(ctx, "endpoint")
	})
}

func (s *policyController) loadPendingManagedEndpointPolicy(ctx context.Context) (agentcontrol.PreparedEndpointPolicy, bool, error) {
	return s.endpointPolicyControl().LoadPending(ctx)
}

func (r *AgentRuntime) setPendingEndpointPolicy(policy agentcontrol.PreparedEndpointPolicy) {
	newEndpointPolicyRuntime(r, nil, nil).SetPendingEndpointPolicy(policy)
}

func (r *AgentRuntime) completePendingEndpointPolicy(ctx context.Context, intent contract.CollectionIntent) error {
	return agentcontrol.NewEndpointPolicyController(newEndpointPolicyRuntime(r, nil, nil)).CompletePending(ctx, intent)
}

func policyResultAck(result agentcontrol.Result) *controlplanev1.ControlAck {
	ack := &controlplanev1.ControlAck{
		RequestId: result.RequestID, TenantId: result.TenantID, AgentId: result.AgentID,
		Status: result.Status, Message: result.Message, PolicyId: result.PolicyID, PolicyVersion: result.Version,
		Details: append([]string(nil), result.Details...), ReportJson: result.ReportJSON,
	}
	for _, section := range result.Sections {
		ack.Sections = append(ack.Sections, &controlplanev1.AppliedSection{
			Name: section.Name, Status: section.Status, Message: section.Message,
			RequiresRestart: section.RequiresRestart, Details: append([]string(nil), section.Details...), ReportJson: section.ReportJSON,
		})
	}
	return ack
}

func setupPendingEndpointPolicyTest(t *testing.T) (*localstore.Store, *AgentRuntime, *policyController) {
	t.Helper()
	store := openEndpointPolicyStore(t)
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	sensor := &applyErrorSensor{err: errors.New("sensor unavailable")}
	runner := newEndpointPolicyRunner(t, store, sensor)
	runner.setEndpointPolicy(standalone)
	return store, runner, newPolicyController(runner, sensorruntime.New(sensor), nil)
}

func openEndpointPolicyStore(t *testing.T) *localstore.Store {
	t.Helper()
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newEndpointPolicyRunner(t *testing.T, store *localstore.Store, sensor contract.Sensor) *AgentRuntime {
	t.Helper()
	runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "device-a", TenantID: "local"}, Telemetry: config.DefaultTelemetryConfig()}, Sensor: sensor, localStore: store, capability: contract.Capability{Backend: "fake", SupportsExec: true}, reportUnenrollment: func(context.Context) (bool, error) { return true, nil }}
	installTestDetection(t, runner)
	return runner
}

func parseEndpointPolicy(t *testing.T, document string) agentpolicy.EndpointPolicy {
	t.Helper()
	policy, err := agentpolicy.ParseEndpointPolicy([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func managedPolicyRequest(policyID string, version uint64) *controlplanev1.ApplyPolicyRequest {
	document := `{"policy_id":"` + policyID + `","version":` + fmt.Sprint(version) + `,"collection":{"behaviors":["process.exec"]},"detection":{"rulesets":[{"ref":"ruleset:cep-endpoint"}]},"telemetry":{},"response":{}}`
	return &controlplanev1.ApplyPolicyRequest{PolicyJson: document}
}

type applyErrorSensor struct{ err error }

func (s *applyErrorSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: "fake", SupportsExec: true}, nil
}
func (s *applyErrorSensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{}, s.err
}
func (s *applyErrorSensor) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return nil, s.err
}
func (s *applyErrorSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "fake"), nil
}
func (s *applyErrorSensor) Health(context.Context) (contract.Health, error) {
	health := contract.Health{Backend: "fake"}
	if s.err != nil {
		health.LastError = s.err.Error()
	}
	return health, nil
}
