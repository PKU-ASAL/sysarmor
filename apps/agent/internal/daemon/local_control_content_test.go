package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/event/normalize"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestLocalControlApplyListGetContent(t *testing.T) {
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

	client := newUnixControlClient(t, socketPath)
	contentJSON := `{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-ip-feed","version":"2026.06.17.1"},
		"spec":{"value_type":"ip","values":["203.0.113.10"]}
	}`
	ack, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-content"},
		ContentJson:   contentJSON,
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatalf("ApplyContent() error = %v", err)
	}
	if ack.Status != "applied" || ack.PolicyId != "ioc:c2-ip-feed" {
		t.Fatalf("ack = %+v", ack)
	}
	list, err := client.ListContent(context.Background(), &controlplanev1.ListContentRequest{Kind: "iocpack"})
	if err != nil {
		t.Fatalf("ListContent() error = %v", err)
	}
	found := false
	for _, record := range list.GetRecords() {
		found = found || record.GetRef() == "ioc:c2-ip-feed"
	}
	if !found {
		t.Fatalf("list = %+v", list)
	}
	got, err := client.GetContent(context.Background(), &controlplanev1.GetContentRequest{Ref: "ioc:c2-ip-feed"})
	if err != nil {
		t.Fatalf("GetContent() error = %v", err)
	}
	if got.GetRecord().GetVersion() != "2026.06.17.1" || got.GetRecord().GetRawJson() == "" {
		t.Fatalf("get = %+v", got)
	}
}

func TestDetectionPolicyWaitsForContentTransaction(t *testing.T) {
	runner := &AgentRuntime{
		Config:     config.Config{Agent: config.AgentConfig{TenantID: "default"}},
		capability: contract.Capability{Backend: "fake", SupportsExec: true},
	}
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	ensureTestLocalStore(t, runner)
	controller := newApplicationPolicyController(runner, nil, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	go runner.withDetectionUpdateTransaction(func() {
		entered <- struct{}{}
		<-release
	})
	<-entered
	done := make(chan agentcontrol.Result, 1)
	go func() {
		done <- controller.ApplyPolicy(context.Background(), agentcontrol.PolicyCommand{
			Context: agentcontrol.RequestContext{TenantID: "default"}, PolicyType: "detection", Source: agentcontrol.PolicySourceStandalone,
			Document: `{"policy_id":"concurrent-policy","version":2,"mode":"observe"}`,
		})
	}()
	select {
	case ack := <-done:
		t.Fatalf("detection policy completed during content transaction: %+v", ack)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("detection policy did not complete after content transaction")
	}
}

func TestLocalControlContentApplyRebuildsDetection(t *testing.T) {
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
	contentJSON := `{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-control-port-feed","version":"local-9443"},
		"spec":{"value_type":"port","values":["9443"]}
	}`
	ack, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-content-rebuild"},
		ContentJson:   contentJSON,
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatalf("ApplyContent() error = %v", err)
	}
	if ack.GetStatus() != "applied" {
		t.Fatalf("ApplyContent() ack = %+v", ack)
	}
	if record, ok := runner.contentStore().Get("ioc:c2-control-port-feed"); !ok || record.Version != "local-9443" {
		t.Fatalf("content record = %+v ok=%t", record, ok)
	}

	norm := normalize.New("agent-a", "host-a", nil)
	batch := appendEndpointEventForTest(t, runner, bus, norm, sensorEventEnvelope("network.connect", 100, "/bin/bash", "", "10.66.0.99:9443"))
	if len(batch.GetSignals()) == 0 {
		t.Fatal("signals after content update = none")
	}
	signalStream, err := client.WatchSignals(context.Background(), &controlplanev1.WatchSignalsRequest{IncludeRecent: true, Limit: 1, RuleId: "reverse_shell_pattern", Where: "endpoint"})
	if err != nil {
		t.Fatalf("WatchSignals() error = %v", err)
	}
	frame, err := signalStream.Recv()
	if err != nil {
		t.Fatalf("signal Recv() error = %v", err)
	}
	var gotVersion string
	for _, ref := range frame.GetSignal().GetIocRefs() {
		if ref.GetRef() == "ioc:c2-control-port-feed" {
			gotVersion = ref.GetVersion()
		}
	}
	if gotVersion != "local-9443" {
		t.Fatalf("signal ioc version = %q, want local-9443; signal=%+v", gotVersion, frame.GetSignal())
	}
}

func TestLocalControlContentRebuildFailureKeepsPreviousDetection(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
		},
		Sensor:     &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		capability: contract.Capability{Backend: "fake", SupportsExec: true, SupportsFile: true, SupportsConnect: true},
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
	good := `{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-control-port-feed","version":"good-9443"},
		"spec":{"value_type":"port","values":["9443"]}
	}`
	goodAck, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-good-content"},
		ContentJson:   good,
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatalf("ApplyContent(good) error = %v", err)
	}
	if goodAck.GetStatus() != "applied" {
		t.Fatalf("good content ack = %+v", goodAck)
	}
	badAck, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-bad-content"},
		ContentJson:   badRuntimeRulePackJSON(),
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatalf("ApplyContent(bad) error = %v", err)
	}
	if badAck.GetStatus() != "rejected" || !strings.Contains(badAck.GetMessage(), "detection rebuild failed") {
		t.Fatalf("bad content ack = %+v", badAck)
	}
	if _, ok := runner.contentStore().Get("rulepack:bad-runtime"); ok {
		t.Fatalf("rejected content was committed")
	}

	norm := normalize.New("agent-a", "host-a", nil)
	batch := appendEndpointEventForTest(t, runner, bus, norm, sensorEventEnvelope("file.write", 100, "/usr/bin/curl", "/dev/shm/kept.sh", ""))
	if len(batch.GetSignals()) != 1 || batch.GetSignals()[0].GetSignal().GetName() != "payload_dropped" {
		t.Fatalf("signals after rejected rebuild = %+v, want previous detection engine still active", batch.GetSignals())
	}
	health, err := client.Health(context.Background(), &controlplanev1.HealthRequest{Context: &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"}})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.GetDetection().GetLastApplyStatus() != "rejected" || !strings.Contains(health.GetDetection().GetLastApplyError(), "bad_runtime_rule") {
		t.Fatalf("detection health = %+v", health.GetDetection())
	}
	for _, ref := range health.GetDetection().GetContentRefs() {
		if ref.GetRef() == "rulepack:bad-runtime" {
			t.Fatalf("detection health includes rejected content ref: %+v", health.GetDetection())
		}
	}
}

func TestLocalControlDetectionPolicyRebuildFailureKeepsPreviousPolicy(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
		},
		Sensor:     &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		capability: contract.Capability{Backend: "fake", SupportsExec: true, SupportsFile: true, SupportsConnect: true},
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
	if _, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-bad-rulepack"},
		ContentJson:   badRuntimeRulePackJSON(),
		AllowUnsigned: true,
	}); err != nil {
		t.Fatalf("ApplyContent(bad rulepack not enabled) error = %v", err)
	}
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-bad-detection-policy"},
		PolicyType: "detection",
		PolicyJson: `{
			"policy_id":"bad-runtime-policy",
			"version":9,
			"mode":"observe",
			"rulesets":[{"ref":"ruleset:bad-runtime","enabled":true}]
		}`,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy(bad detection) error = %v", err)
	}
	if ack.GetStatus() != "rejected" {
		t.Fatalf("ack = %+v, want rejected", ack)
	}
	if runner.activePolicy().Detection.PolicyID == "bad-runtime-policy" {
		t.Fatalf("bad detection policy replaced active policy")
	}
	batch := appendEndpointEventForTest(t, runner, bus, normalize.New("agent-a", "host-a", nil), sensorEventEnvelope("file.write", 100, "/usr/bin/curl", "/dev/shm/kept-policy.sh", ""))
	if len(batch.GetSignals()) != 1 || batch.GetSignals()[0].GetSignal().GetName() != "payload_dropped" {
		t.Fatalf("signals after rejected policy = %+v, want previous detection policy still active", batch.GetSignals())
	}
}

func badRuntimeRulePackJSON() string {
	return `{
		"api_version":"sysarmor.content/v1",
		"kind":"rulepack",
		"metadata":{"id":"rulepack:bad-runtime","version":"bad-v1"},
		"spec":{"rulesets":[{"id":"ruleset:cep-endpoint","version":"v1","rules":[{
			"rule_id":"bad_runtime_rule",
			"version":1,
			"severity":"high",
			"runtime":{"type":"made_up_runtime"}
		}]}]}
	}`
}

type recordingCollectionSensor struct {
	healthOnlySensor
	lastIntent contract.CollectionIntent
}

func (s *recordingCollectionSensor) Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	s.lastIntent = intent
	return s.healthOnlySensor.Apply(ctx, intent)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
