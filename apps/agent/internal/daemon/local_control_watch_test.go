package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestLocalControlWatchRecentEventsAndSignals(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
		},
		Sensor:     &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		capability: contract.Capability{Backend: "fake", SupportsExec: true},
	}
	rt := sensorruntime.New(runner.Sensor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus, batcher, sender := newTestTelemetry(t, runner)
	stop, err := runner.startLocalControlServer(ctx, rt, bus, batcher, sender, time.Now())
	if err != nil {
		t.Fatalf("startLocalControlServer() error = %v", err)
	}
	defer stop()

	norm := eventadapter.NewEventNormalizer("agent-a", "host-a", eventadapter.EventNormalizerOptions{TenantID: "default", ScopeType: "host", Labels: map[string]string{"benchmark_run": "run-a"}})
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	appendEndpointEventForTest(t, runner, bus, norm, sensorEventEnvelope("file.write", 100, "/usr/bin/curl", "/dev/shm/x.sh", ""))

	client := newUnixControlClient(t, socketPath)
	eventStream, err := client.WatchEvents(context.Background(), &controlplanev1.WatchEventsRequest{IncludeRecent: true, Limit: 1, Behavior: "file.write"})
	if err != nil {
		t.Fatalf("WatchEvents() error = %v", err)
	}
	eventFrame, err := eventStream.Recv()
	if err != nil {
		t.Fatalf("event Recv() error = %v", err)
	}
	if eventFrame.GetEvent().GetBehavior() != "file.write" || eventFrame.GetAgentId() != "agent-a" {
		t.Fatalf("event frame = %+v", eventFrame)
	}
	if eventFrame.GetEvent().GetTenantId() != "default" || eventFrame.GetEvent().GetScope().GetType() != "host" {
		t.Fatalf("event provenance tags = %+v", eventFrame.GetEvent())
	}
	if eventFrame.GetEvent().GetLabels()["benchmark_run"] != "run-a" {
		t.Fatalf("event labels = %+v", eventFrame.GetEvent().GetLabels())
	}
	eventGet, err := client.GetEvent(context.Background(), &controlplanev1.GetEventRequest{EventId: eventFrame.GetEvent().GetId()})
	if err != nil {
		t.Fatalf("GetEvent() error = %v", err)
	}
	if eventGet.GetFrame().GetEvent().GetId() != eventFrame.GetEvent().GetId() {
		t.Fatalf("GetEvent frame = %+v, want event id %q", eventGet.GetFrame(), eventFrame.GetEvent().GetId())
	}
	signalStream, err := client.WatchSignals(context.Background(), &controlplanev1.WatchSignalsRequest{IncludeRecent: true, Limit: 1, RuleId: "payload_dropped", Where: "endpoint"})
	if err != nil {
		t.Fatalf("WatchSignals() error = %v", err)
	}
	signalFrame, err := signalStream.Recv()
	if err != nil {
		t.Fatalf("signal Recv() error = %v", err)
	}
	if signalFrame.GetSignal().GetName() != "payload_dropped" || signalFrame.GetAgentId() != "agent-a" {
		t.Fatalf("signal frame = %+v", signalFrame)
	}
	if len(signalFrame.GetSignal().GetEventRefs()) != 1 || signalFrame.GetSignal().GetEventRefs()[0] != eventFrame.GetEvent().GetId() {
		t.Fatalf("signal event refs = %v, want %s", signalFrame.GetSignal().GetEventRefs(), eventFrame.GetEvent().GetId())
	}
	if signalFrame.GetSignal().GetLabels()["benchmark_run"] != "run-a" {
		t.Fatalf("signal labels = %+v", signalFrame.GetSignal().GetLabels())
	}
	labelStream, err := client.WatchSignals(context.Background(), &controlplanev1.WatchSignalsRequest{
		IncludeRecent: true,
		Limit:         1,
		Filter:        &controlplanev1.WatchFilter{Labels: map[string]string{"benchmark_run": "run-a"}},
	})
	if err != nil {
		t.Fatalf("WatchSignals(label) error = %v", err)
	}
	if _, err := labelStream.Recv(); err != nil {
		t.Fatalf("label signal Recv() error = %v", err)
	}
	afterStream, err := client.WatchSignals(context.Background(), &controlplanev1.WatchSignalsRequest{
		IncludeRecent: true,
		SnapshotOnly:  true,
		Filter:        &controlplanev1.WatchFilter{AfterSequence: signalFrame.GetSequence()},
	})
	if err != nil {
		t.Fatalf("WatchSignals(after sequence) error = %v", err)
	}
	if frame, err := afterStream.Recv(); err == nil {
		t.Fatalf("after sequence returned frame %+v, want no recent frames", frame)
	}
}
