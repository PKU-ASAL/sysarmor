package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	domainhealth "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/health"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

func TestRuntimeRunsWithTetragonJSONLSource(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	eventPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	if err := os.WriteFile(eventPath, []byte(raw+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Sensor:    config.SensorConfig{Backend: "tetragon", Mode: "managed", Version: "test", PolicyPath: policyPath, EventSource: eventPath, ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
		Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: time.Second, RequestTimeout: time.Second, MaxInflight: 1}},
		Health:    config.HealthConfig{Interval: time.Hour},
	}
	runner := newConfiguredTestRuntime(t, cfg)
	installTestDetection(t, runner)
	var out safeBuffer
	runRuntimeUntilOutput(t, runner, &out, "agent runtime event")
	got := out.String()
	for _, want := range []string{"sensor=tetragon", "agent runtime event"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestRuntimeTetragonRequiresEventSource(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Sensor:    config.SensorConfig{Backend: "tetragon", Mode: "managed", PolicyPath: policyPath, EventTransport: "tetra", ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
		Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: time.Second, RequestTimeout: time.Second, MaxInflight: 1}},
		Health:    config.HealthConfig{Interval: time.Hour},
	}
	runner := newConfiguredTestRuntime(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := runner.Run(ctx, Options{})
	if err == nil {
		t.Fatal("Run() error = nil")
	}
}

func TestRuntimeProcessesTamperSignalFromHealth(t *testing.T) {
	runner := &Coordinator{
		Config: config.Config{
			Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
			Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", ObserveOnly: true, RestartWindow: time.Hour},
			Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Hour},
			Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Hour, RetryMax: time.Hour, RequestTimeout: 5 * time.Millisecond, MaxInflight: 1}},
			Health:    config.HealthConfig{Interval: 5 * time.Millisecond},
		},
		Sensor: &healthOnlySensor{health: contract.Health{
			Backend:        "tetragon",
			Installed:      true,
			PolicyLoaded:   true,
			Running:        false,
			RestartCount:   3,
			LastExitReason: "exit status 7",
			LastError:      "exit status 7",
		}},
	}
	runner.wireComponents()
	health := domainhealth.Snapshot{
		Runtime: domainhealth.Runtime{
			AgentID: runner.Config.Agent.ID, HostID: runner.Config.Agent.HostID,
			TenantID: runner.Config.Agent.TenantID, PolicyID: runner.policyState.activePolicy().PolicyID,
			PolicyVersion: runner.policyState.activePolicy().Version, PolicyMode: runner.healthRuntime().policyMode(),
		},
		Status: domainhealth.StatusDegraded, UptimeSeconds: 1, ObservedAt: time.Now().UTC(),
		Sensor: domainhealth.Sensor{
			Backend:        "tetragon",
			Installed:      true,
			PolicyLoaded:   true,
			Running:        false,
			RestartCount:   3,
			LastExitReason: "exit status 7",
			LastError:      "exit status 7",
		},
	}
	domainSignal := (&domainhealth.TamperDetector{}).Evaluate(health, time.Now().UTC(), domainhealth.TamperOptions{
		MaxRestarts:      uint64(runner.Config.Sensor.MaxRestarts),
		MaxParseErrors:   runner.Config.Sensor.MaxParseErrors,
		MaxDroppedEvents: runner.Config.Sensor.MaxDroppedEvents,
	})
	if domainSignal == nil {
		t.Fatal("tamper Evaluate() = nil")
	}
	sig := contractadapter.Signal(*domainSignal)
	batch := appendEndpointSignalsForTest(t, runner, nil, []*signalv1.Signal{sig})
	sig = batch.GetSignals()[0].GetSignal()
	if sig.GetName() != domainhealth.SensorTamperSignalName || sig.GetStage() != signalv1.SignalStage_SIGNAL_STAGE_CONCLUSION ||
		sig.GetDetectorKind() != signalv1.DetectorKind_DETECTOR_KIND_SYSTEM || sig.GetWhere() != signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT {
		t.Fatalf("tamper signal = %+v", sig)
	}
	if sig.GetLabels()["policy_id"] != runner.policyState.activePolicy().PolicyID || sig.GetLabels()["policy_version"] != fmt.Sprint(runner.policyState.activePolicy().Version) {
		t.Fatalf("tamper policy labels = %+v", sig.GetLabels())
	}
}

func TestRuntimeMarksHealthDegradedWhenParseThresholdExceeded(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: policyPath, ObserveOnly: true, MaxParseErrors: 1, RestartWindow: time.Hour},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Hour},
		Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Hour, RetryMax: time.Hour, RequestTimeout: 5 * time.Millisecond, MaxInflight: 1}},
		Health:    config.HealthConfig{Interval: time.Hour},
	}
	runner := &Coordinator{
		Config: cfg,
		Sensor: &healthOnlySensor{health: contract.Health{
			Backend:      "tetragon",
			Installed:    true,
			PolicyLoaded: true,
			Running:      true,
			ParseErrors:  2,
		}},
	}
	runner.wireComponents()
	runner.managementState.setRuntimeIdentity(runtimeIdentity{AgentID: "device-a", HostID: "host-a", TenantID: "local"})
	if err := runner.managementState.reconcileManagementContext(sqlite.Enrollment{State: sqlite.StateManaged, EnrollmentID: "enroll-a", AgentID: "managed-agent", TenantID: "managed-tenant"}); err != nil {
		t.Fatal(err)
	}
	rt := sensorruntime.New(runner.Sensor)
	if _, err := rt.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Apply(context.Background(), contract.CollectionIntent{ObserveOnly: true}); err != nil {
		t.Fatal(err)
	}
	bus := telemetryadapter.NewBus(1024)
	batcher := telemetryadapter.NewBatcher(runner.telemetryState.newBatchBuilder().NewBatch, cfg.Telemetry.MaxBatchItems, cfg.Telemetry.FlushInterval, 16)
	sender := telemetryadapter.NewRuntimeSender(batcher, noopUploader{}, 0, 0)
	health := runner.healthRuntime().collect(context.Background(), rt, bus, batcher, sender, time.Now())
	if health.Status != "degraded" || health.Sensor.ParseErrors != 2 {
		t.Fatalf("health = %+v", health)
	}
	if health.AgentID != "managed-agent" || health.TenantID != "managed-tenant" || health.HostID != "host-a" {
		t.Fatalf("managed health identity = %+v", health)
	}
}

func TestNewBatchSenderAcceptsConfiguredTimeout(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
	}{
		{name: "grpc", transport: "grpc"},
		{name: "local", transport: "local"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, err := newBatchSender("127.0.0.1:9443", tc.transport, 250*time.Millisecond, "dev-token", tlsconfig.ClientConfig{})
			if err != nil {
				t.Fatalf("newBatchSender() error = %v", err)
			}
			if up == nil {
				t.Fatal("newBatchSender() = nil")
			}
		})
	}
}
