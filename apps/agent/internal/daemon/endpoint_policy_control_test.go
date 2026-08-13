package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
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
	application := newEndpointPolicyApplication(runner, nil, nil)
	candidate, err := application.PrepareEndpoint(t.Context(), string(document), "managed")
	if err != nil {
		t.Fatalf("prepare manager default endpoint policy: %v", err)
	}
	prepared, err := endpointPrepared(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.endpoint.Detection.RuleSets) != 1 || prepared.endpoint.Detection.RuleSets[0].Ref != "ruleset:cep-endpoint" {
		t.Fatalf("manager default rulesets = %+v", prepared.endpoint.Detection.RuleSets)
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
	controller := agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, sensorruntime.New(runner.Sensor), nil))
	result := controller.Apply(t.Context(), managedPolicyCommand("managed", 5))
	if result.Status == "rejected" {
		t.Fatalf("manager policy result=%+v", result)
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
	application := newEndpointPolicyApplication(runner, sensorruntime.New(runner.Sensor), nil)
	if err := application.RestoreStandalone(t.Context(), func(ctx context.Context) error {
		return store.ActivateStandalonePolicy(ctx, "endpoint")
	}); err == nil {
		t.Fatal("managed enrollment restored standalone policy without revocation")
	}
	_, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != localstore.PolicySourceManaged || runner.currentEndpointPolicy().PolicyID != "managed" {
		t.Fatalf("source=%q ok=%t policy=%+v err=%v", source, ok, runner.currentEndpointPolicy(), err)
	}
}

func TestPromoteManagedAuthorityRejectsUnexpectedEnrollmentState(t *testing.T) {
	store := openEndpointPolicyStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	application := newEndpointPolicyApplication(runner, sensorruntime.New(runner.Sensor), nil)

	err := application.PromoteManaged(t.Context(), nil)

	if err == nil || !strings.Contains(err.Error(), "requires managed enrollment") {
		t.Fatalf("error=%v", err)
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
	controller := agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, sensorruntime.New(runner.Sensor), nil))
	result := controller.Apply(t.Context(), managedPolicyCommand("managed", 5))
	got, err := store.Enrollment(t.Context())
	if err != nil || result.Status == "rejected" || got.State != localstore.StateManaged || runner.currentIdentity().AgentID != "agent-a" {
		t.Fatalf("result=%+v enrollment=%+v identity=%+v err=%v", result, got, runner.currentIdentity(), err)
	}
}

func TestManagerPolicyPersistsPendingWhenSensorUnavailable(t *testing.T) {
	store, _, _, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	result := controller.Apply(t.Context(), managedPolicyCommand("managed", 5))
	desired, status, ok, err := store.DesiredPolicy(t.Context(), "endpoint", localstore.PolicySourceManaged)
	active, source, activeOK, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	enrollment, enrollmentErr := store.Enrollment(t.Context())
	if result.Status != "pending" || err != nil || !ok || status != localstore.PolicyStatusPending || desired.Version != 5 {
		t.Fatalf("result=%+v desired=%+v status=%q ok=%t err=%v", result, desired, status, ok, err)
	}
	if activeErr != nil || !activeOK || source != localstore.PolicySourceStandalone || active.Version != 1 || enrollmentErr != nil || enrollment.State != localstore.StateEnrolling {
		t.Fatalf("active=%+v source=%q ok=%t enrollment=%+v errors=%v/%v", active, source, activeOK, enrollment, activeErr, enrollmentErr)
	}
}

func TestCurrentPolicyReportsPendingManagedPolicy(t *testing.T) {
	store, runner, runtime, endpointController := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	result := endpointController.Apply(t.Context(), managedPolicyCommand("managed", 5))
	if result.Status != "pending" {
		t.Fatalf("result=%+v", result)
	}
	controller := newApplicationPolicyController(runner, runtime, nil)
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
	store, runner, runtime, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	result := controller.Apply(t.Context(), managedPolicyCommand("managed", 5))
	if result.Status != "pending" {
		t.Fatalf("result=%+v", result)
	}
	server := &localStatusService{runner: runner, runtime: runtime}
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
	store, runner, runtime, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", TenantID: "local"})
	result := controller.Apply(t.Context(), managedPolicyCommand("managed", 5))
	if result.Status != "pending" {
		t.Fatalf("pending result=%+v", result)
	}
	application := newEndpointPolicyApplication(runner, runtime, nil)
	intent, ok, err := application.PendingIntent(t.Context())
	if err != nil || !ok {
		t.Fatalf("pending intent ok=%t err=%v", ok, err)
	}
	if err := application.ResumeApplied(t.Context(), intent); err != nil {
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
	store, runner, runtime, _ := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	sensor := runner.Sensor.(*applyErrorSensor)
	sensor.err = nil
	batcher := telemetryadapter.NewBatcher(nil, 10, time.Hour, 2, 12345)
	controller := newApplicationPolicyController(runner, runtime, batcher)
	command := managedPolicyCommand("managed", 5)

	result := controller.ApplyPolicy(t.Context(), command)

	if result.Status == "rejected" || result.Status == "pending" {
		t.Fatalf("result=%+v", result)
	}
	if got := batcher.Stats().MaxBytes; got != 12345 {
		t.Fatalf("batch max bytes=%d want 12345", got)
	}
}

func TestSuccessfulManagerPolicySupersedesOlderPendingPolicy(t *testing.T) {
	store, runner, _, controller := setupPendingEndpointPolicyTest(t)
	defer store.Close()
	sensor := runner.Sensor.(*applyErrorSensor)
	first := controller.Apply(t.Context(), managedPolicyCommand("managed-old", 5))
	if first.Status != "pending" {
		t.Fatalf("first result=%+v", first)
	}
	sensor.err = nil
	second := controller.Apply(t.Context(), managedPolicyCommand("managed-new", 6))
	_, _, pending, pendingErr := store.DesiredPolicy(t.Context(), "endpoint", localstore.PolicySourceManaged)
	active, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if second.Status == "rejected" || pending || pendingErr != nil {
		t.Fatalf("second result=%+v storedPending=%t err=%v", second, pending, pendingErr)
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
	application := newEndpointPolicyApplication(runner, nil, nil)
	candidate, ok, err := application.PendingManaged(t.Context())
	prepared, prepareErr := endpointPrepared(candidate)
	if err != nil || prepareErr != nil || !ok || prepared.endpoint.PolicyID != "managed" || len(prepared.intent.Behaviors) != 1 {
		t.Fatalf("prepared=%+v ok=%t errors=%v/%v", prepared, ok, err, prepareErr)
	}
}

func TestRestoreDurableManagedPolicyAfterRuntimePromotionFailure(t *testing.T) {
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
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
	runner.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", TenantID: "local"})
	application := newEndpointPolicyApplication(runner, sensorruntime.New(runner.Sensor), nil)

	intent, ok, err := application.PendingIntent(t.Context())
	if err != nil || !ok {
		t.Fatalf("pending intent ok=%t err=%v", ok, err)
	}
	if err := application.ResumeApplied(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	if runner.currentIdentity().AgentID != "agent-a" || runner.currentEndpointPolicy().PolicyID != "managed" {
		t.Fatalf("identity=%+v policy=%+v", runner.currentIdentity(), runner.currentEndpointPolicy())
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
	application := newEndpointPolicyApplication(runner, nil, nil)
	controller := agentcontrol.NewEndpointPolicyController(application)
	command := managedPolicyCommand("managed", 5)
	candidate, err := application.PrepareEndpoint(t.Context(), command.Document, "managed")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := endpointPrepared(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveDesiredManagedEndpointPolicy(t.Context(), store, pending.endpoint); err != nil {
		t.Fatal(err)
	}
	manager := sensorruntime.New(runner.Sensor)
	supervisor := sensorruntime.NewSubscriptionSupervisor(sensorruntime.AdaptManager(manager), pending.intent, sensorruntime.RetryOptions{})
	runner.setSensorSupervisor(supervisor)
	callbackReady := make(chan struct{})
	allowCallback := make(chan struct{})
	supervisor.OnApplied(func(ctx context.Context, intent contract.CollectionIntent) error {
		close(callbackReady)
		<-allowCallback
		return application.ResumeApplied(ctx, intent)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	supervisor.Start(ctx)
	<-callbackReady
	done := make(chan agentcontrol.Result, 1)
	go func() { done <- controller.Apply(ctx, command) }()
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
	case result := <-done:
		if result.Status == "rejected" {
			t.Fatalf("duplicate policy result=%+v", result)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("duplicate managed policy deadlocked startup pending activation")
	}
}

func setupPendingEndpointPolicyTest(t *testing.T) (*localstore.Store, *AgentRuntime, sensorruntime.Runtime, *agentcontrol.EndpointPolicyController) {
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
	runtime := sensorruntime.New(sensor)
	controller := agentcontrol.NewEndpointPolicyController(newEndpointPolicyApplication(runner, runtime, nil))
	return store, runner, runtime, controller
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

func managedPolicyCommand(policyID string, version uint64) agentcontrol.PolicyCommand {
	document := `{"policy_id":"` + policyID + `","version":` + fmt.Sprint(version) + `,"collection":{"behaviors":["process.exec"]},"detection":{"rulesets":[{"ref":"ruleset:cep-endpoint"}]},"telemetry":{},"response":{}}`
	return agentcontrol.PolicyCommand{PolicyType: "endpoint", Document: document, Source: agentcontrol.PolicySourceManaged}
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
