package runtime

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestLocalControlServerOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &Runtime{
		Config: config.Config{
			Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control:   config.ControlConfig{SocketPath: socketPath},
			Sensor:    config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
			Telemetry: config.DefaultTelemetryConfig(),
		},
		Sensor: &healthOnlySensor{health: contract.Health{
			Backend:      "fake",
			Running:      true,
			Installed:    true,
			PolicyLoaded: true,
		}},
		capability: contract.Capability{
			Backend:         "fake",
			Version:         "test",
			SupportsExec:    true,
			SupportsConnect: true,
			SupportsHealth:  true,
			Collection: []contract.CollectionBehaviorCapability{{
				Behavior: "network.connect",
				Fields:   []string{"socket.port", "process.binary", "lineage_id"},
			}},
		},
	}
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	rt := sensorruntime.New(runner.Sensor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus, batcher, sender := newTestTelemetry(t, runner)
	stop, err := runner.startLocalControlServer(ctx, rt, bus, batcher, sender, time.Now())
	if err != nil {
		t.Fatalf("startLocalControlServer() error = %v", err)
	}
	defer stop()

	client := newUnixControlClient(t, socketPath)
	health, err := client.Health(context.Background(), &controlplanev1.HealthRequest{Context: &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"}})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.AgentId != "agent-a" || health.Sensor.Backend != "fake" || !health.Sensor.Running {
		t.Fatalf("health = %+v", health)
	}
	if health.GetStreams().GetEventCapacity() == 0 || health.GetStreams().GetSignalCapacity() == 0 {
		t.Fatalf("stream health = %+v", health.GetStreams())
	}
	if health.GetTelemetryBatcher().GetQueuedBatches() != 0 {
		t.Fatalf("telemetry batcher health = %+v", health.GetTelemetryBatcher())
	}
	cap, err := client.Capability(context.Background(), &controlplanev1.CapabilityRequest{})
	if err != nil {
		t.Fatalf("Capability() error = %v", err)
	}
	if cap.AgentId != "agent-a" || !cap.Sensor.SupportsExec || len(cap.SupportedPolicySections) == 0 {
		t.Fatalf("capability = %+v", cap)
	}
	if len(cap.GetCollectionBehaviors()) != 1 || cap.GetCollectionBehaviors()[0].GetBehavior() != "network.connect" {
		t.Fatalf("collection behavior capability = %+v", cap.GetCollectionBehaviors())
	}
	policy, err := client.CurrentPolicy(context.Background(), &controlplanev1.CurrentPolicyRequest{})
	if err != nil {
		t.Fatalf("CurrentPolicy() error = %v", err)
	}
	if policy.PolicyId != policymodel.DefaultPolicyID || policy.RawJson == "" {
		t.Fatalf("policy = %+v", policy)
	}
	profile, err := client.DebugProfile(context.Background(), &controlplanev1.DebugProfileRequest{
		Context:     &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"},
		ProfileType: "cpu",
		Seconds:     1,
		Label:       "unit-test",
	})
	if err != nil {
		t.Fatalf("DebugProfile() error = %v", err)
	}
	if profile.GetProfileType() != "cpu" || profile.GetSeconds() != 1 || profile.GetLabel() != "unit-test" || len(profile.GetProfile()) == 0 {
		t.Fatalf("profile = %+v len=%d", profile, len(profile.GetProfile()))
	}
}

func TestHealthResponseIncludesDefaultManifestVersion(t *testing.T) {
	response := healthResponse(agenthealth.AgentHealth{Detection: agenthealth.DetectionHealth{DefaultManifestVersion: "release-v1"}})
	if got := response.GetDetection().GetDefaultManifestVersion(); got != "release-v1" {
		t.Fatalf("health manifest version = %q, want release-v1", got)
	}
}

func TestHealthResponseMapsStorageAndLifecycleFromDomainSnapshot(t *testing.T) {
	response := healthResponseSnapshot(domainhealth.Snapshot{
		Status:    domainhealth.StatusDegraded,
		Storage:   domainhealth.Storage{Available: true, Mode: "managed", DeviceID: "device-a", UploadSegmentID: 7},
		Lifecycle: domainhealth.Lifecycle{Mode: "unenrolling", TransitionPhase: "revocation_pending", TransitionPending: true},
	})
	if response.GetLocalStore().GetDeviceId() != "device-a" || response.GetLocalStore().GetUploadSegmentId() != 7 {
		t.Fatalf("local store=%+v", response.GetLocalStore())
	}
	if response.GetManagementLifecycle().GetTransitionPhase() != "revocation_pending" || response.GetStatus() != "degraded" {
		t.Fatalf("lifecycle=%+v status=%q", response.GetManagementLifecycle(), response.GetStatus())
	}
}

func TestHealthResponseOmitsUnavailableStorage(t *testing.T) {
	response := healthResponseSnapshot(domainhealth.Snapshot{})
	if response.GetLocalStore() != nil {
		t.Fatalf("local store=%+v", response.GetLocalStore())
	}
}

func TestManagementLifecycleStatusRejectsInvalidState(t *testing.T) {
	root := t.TempDir()
	store, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(t.Context(), "PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "UPDATE enrollment SET state='corrupt' WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}

	runner := &Runtime{localStore: store}
	_, err = (&runtimeHealthSource{runner: runner}).Lifecycle(t.Context())
	if err == nil || !strings.Contains(err.Error(), "unsupported management state") {
		t.Fatalf("error=%v", err)
	}
}

func TestHealthReportsUnenrollmentLifecycle(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.BeginUnenrollment(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordUnenrollmentError(t.Context(), "manager unavailable"); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{
		Backend: "fake", Installed: true, Running: true, PolicyLoaded: true,
	}})
	bus, batcher, sender := newTestTelemetry(t, runner)
	server := &localStatusService{runner: runner, runtime: sensorruntime.New(runner.Sensor), bus: bus, batcher: batcher, sender: sender, startedAt: time.Now()}

	response, err := server.Health(t.Context(), &controlplanev1.HealthRequest{})
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := response.GetManagementLifecycle()
	if lifecycle.GetMode() != "unenrolling" || lifecycle.GetTransitionPhase() != "revocation_pending" ||
		lifecycle.GetRevocationConfirmed() || lifecycle.GetLastTransitionError() != "manager unavailable" || lifecycle.GetUpdatedAt() == "" {
		t.Fatalf("management lifecycle = %+v", lifecycle)
	}
	if response.GetStatus() != "degraded" {
		t.Fatalf("health status = %q, want degraded", response.GetStatus())
	}
}
