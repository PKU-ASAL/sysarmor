package daemon

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestAgentRuntimeUploadsFakeSensorEvent(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: policyPath, ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
		Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: time.Second, RequestTimeout: time.Second, MaxInflight: 1}},
		Health:    config.HealthConfig{Interval: time.Hour},
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	installTestDetection(t, runner)
	var out bytes.Buffer
	runDaemonUntilUploadedBatch(t, runner, &out)
	got := out.String()
	for _, want := range []string{"agent daemon started", "sensor=fake", "agent daemon event"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output %q does not contain %q", got, want)
		}
	}
}

func TestStandaloneRuntimePersistsBeforeAcknowledging(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.json")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Local:     config.LocalConfig{StatePath: filepath.Join(dir, "state"), Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: time.Second, RequestTimeout: time.Second, MaxInflight: 1}, Storage: config.LocalStorageConfig{MaxBytes: 1 << 30, MinFreeBytes: 1, SegmentSize: 1 << 20, SignalMaxCount: 1000}},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: policyPath, ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
		Health:    config.HealthConfig{Interval: time.Second},
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.localStore.Close()
	if runner.Config.Agent.ID == "" || runner.Config.Agent.HostID == "" || runner.Config.Agent.TenantID != "local" {
		t.Fatalf("identity=%+v", runner.Config.Agent)
	}
	sender, err := runner.batchSender()
	if err != nil {
		t.Fatal(err)
	}
	batch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{BatchId: "standalone-1", EventSeqStart: 1, EventSeqEnd: 1}}
	ack, err := sender.SendBatch(batch)
	if err != nil || !dataappend.AckCommitted(ack) {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	batches, err := runner.localStore.ReadBatches(t.Context(), localstore.ReadOptions{Limit: 10})
	if err != nil || len(batches) != 1 || batches[0].Batch.GetHeader().GetBatchId() != "standalone-1" {
		t.Fatalf("batches=%+v err=%v", batches, err)
	}
}

func TestStandaloneRuntimeResumesPersistentSequences(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state")
	store := openSequenceStore(t, statePath)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := standaloneTestConfig(t, dir, statePath)
	runner, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runner.localStore.Close()
	if runner.eventSeq != 41 || runner.signalSeq != 17 {
		t.Fatalf("eventSeq=%d signalSeq=%d, want 41/17", runner.eventSeq, runner.signalSeq)
	}
}

func TestEndpointSignalIDsContinueAcrossDetectionReplacement(t *testing.T) {
	runner := &AgentRuntime{signalSeq: 17}
	parent := &eventv1.CanonicalEvent{
		Id: "event-parent", Behavior: "process.exec",
		SubjectProc: &eventv1.ProcessRef{StableId: "node-parent", Binary: "/usr/bin/node"},
	}
	event := &eventv1.CanonicalEvent{
		Id: "event-a", Behavior: "process.exec", ParentStableId: "node-parent",
		SubjectProc: &eventv1.ProcessRef{StableId: "shell-child", Binary: "/bin/bash"},
	}
	policy := &policymodel.DetectionPolicy{RuleSets: []policymodel.RuleSetRef{{Ref: "ruleset:signal-sequence"}}}
	content := detection.ContentSnapshot{Rules: []detection.RuleSpec{{
		RuleID: "signal_sequence_test", RuleSetRef: "ruleset:signal-sequence", RuntimeType: "expr",
		Expr: detection.ExprSpec{Conditions: []detection.ConditionSpec{{Field: "process.binary_name", Op: "eq", Value: "bash"}}},
	}}}
	firstEngine, _ := detection.NewWithRuntime(policy, contract.CollectionIntent{}, content)
	secondEngine, _ := detection.NewWithRuntime(policy, contract.CollectionIntent{}, content)
	firstEngine.Process(parent)
	secondEngine.Process(parent)
	first := runner.dataBatchForEvent(event, firstEngine.Process(event)).GetSignals()[0]
	second := runner.dataBatchForEvent(event, secondEngine.Process(event)).GetSignals()[0]
	if first.GetSequence() != 18 || first.GetSignal().GetId() != "sig-00000000000000000018" {
		t.Fatalf("first signal=%+v", first)
	}
	if second.GetSequence() != 19 || second.GetSignal().GetId() != "sig-00000000000000000019" {
		t.Fatalf("second signal=%+v", second)
	}
}

func TestLocalStoreBatchSenderEnforcesCapacityBeforeAck(t *testing.T) {
	root := t.TempDir()
	store, err := localstore.Open(t.Context(), localstore.Options{
		RootDir: root, MaxBytes: 1, MinFreeBytes: 1, SegmentSize: 128,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for sequence := uint64(1); sequence <= 3; sequence++ {
		batch := &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
			BatchId: fmt.Sprintf("seed-%d", sequence), EventSeqStart: sequence, EventSeqEnd: sequence,
		}}
		if _, err := store.AppendBatch(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
		if err := store.Seal(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveCheckpoint(t.Context(), localstore.Checkpoint{SegmentID: 3}); err != nil {
		t.Fatal(err)
	}

	sender := &localStoreBatchSender{store: store}
	ack, err := sender.SendBatch(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		BatchId: "new-batch", EventSeqStart: 4, EventSeqEnd: 4,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !ack.GetAccepted() {
		t.Fatalf("ack=%+v", ack)
	}
	if _, err := os.Stat(filepath.Join(root, "spool", "0000000000000001.seg")); !os.IsNotExist(err) {
		t.Fatalf("uploaded segment was not reclaimed, stat error=%v", err)
	}
}

func openSequenceStore(t *testing.T, statePath string) *localstore.Store {
	t.Helper()
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: statePath})
	if err != nil {
		t.Fatal(err)
	}
	signal := &dataplanev1.SignalFrame{Sequence: 17, ObservedAt: "2026-07-24T00:00:00Z", Signal: &signalv1.Signal{Id: "sig-00000000000000000017"}}
	batch := &dataplanev1.DataBatch{
		Header:  &dataplanev1.BatchHeader{BatchId: "seed", EventSeqStart: 41, EventSeqEnd: 41, SignalSeqStart: 17, SignalSeqEnd: 17},
		Signals: []*dataplanev1.SignalFrame{signal},
	}
	if _, err := store.AppendBatch(t.Context(), batch); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendSignals(t.Context(), []*dataplanev1.SignalFrame{signal}); err != nil {
		t.Fatal(err)
	}
	return store
}

func standaloneTestConfig(t *testing.T, dir, statePath string) config.Config {
	t.Helper()
	policyPath := filepath.Join(dir, "collection.json")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{
		Local:     config.LocalConfig{StatePath: statePath, Storage: config.LocalStorageConfig{MaxBytes: 1 << 30, MinFreeBytes: 1, SegmentSize: 1 << 20, SignalMaxCount: 1000}},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: policyPath, ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
	}
}

func TestAgentRuntimeUploadsConfiguredLabels(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(testCollectionPolicyJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token", Labels: map[string]string{"scenario": "daemon-scenario"}},
		Manager:   config.ManagerConfig{Address: "local", Transport: "local"},
		Sensor:    config.SensorConfig{Backend: "fake", Mode: "managed", PolicyPath: policyPath, Scope: config.RuntimeScope{Type: "container", Selector: "abc123"}, ObserveOnly: true},
		Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
		Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: time.Second, RequestTimeout: time.Second, MaxInflight: 1}},
		Health:    config.HealthConfig{Interval: time.Hour},
	}
	runner, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	installTestDetection(t, runner)
	batch := runDaemonUntilUploadedBatch(t, runner, nil)
	if got := batch.GetEvents()[0].GetEvent().GetLabels()["scenario"]; got != "daemon-scenario" {
		t.Fatalf("event label scenario = %q", got)
	}
	for _, sig := range batch.GetSignals() {
		signal := sig.GetSignal()
		if got := signal.GetLabels()["scenario"]; got != "daemon-scenario" {
			t.Fatalf("signal %s label scenario = %q", signal.GetName(), got)
		}
	}
}

func TestAgentRuntimeShutdownFlushesTelemetryBestEffort(t *testing.T) {
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token"},
			Sensor:    config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
			Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Hour},
			Local:     config.LocalConfig{Export: config.LocalExportConfig{RequestTimeout: 200 * time.Millisecond, MaxInflight: 1}},
		},
		Sensor:     &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		capability: contract.Capability{Backend: "fake", SupportsHealth: true},
	}
	bus := telemetry.NewBus(16)
	batcher := telemetry.NewBatcher(runner.newDataBatch, 10, time.Hour, 4)
	uploader := newRecordingUploader()
	sender := &telemetry.Sender{Appender: uploader, Batcher: batcher}
	ctx, cancelSender := context.WithCancel(context.Background())
	defer cancelSender()
	go sender.Run(ctx)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{Id: "event-a", AgentId: "agent-a", HostId: "host-a"}}}})

	var out bytes.Buffer
	runner.Out = &out
	rt := sensorruntime.New(runner.Sensor)
	if err := runner.shutdownAndReport(context.Background(), rt, bus, batcher, sender, localHealthReporter{}, time.Now(), cancelSender, func() {}); err != nil {
		t.Fatalf("shutdownAndReport() error = %v", err)
	}
	stats := sender.Stats()
	if !stats.Drained || stats.SentBatches != 1 || len(uploader.ch) != 1 {
		t.Fatalf("sender stats = %+v uploaded=%d", stats, len(uploader.ch))
	}
	if got := out.String(); !strings.Contains(got, "drained=true") || !strings.Contains(got, "timeout=false") {
		t.Fatalf("shutdown output = %q", got)
	}
}

func TestAgentRuntimeRefreshesEndpointPolicy(t *testing.T) {
	cfg := config.Config{
		Agent: config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default", Token: "dev-token", Labels: map[string]string{"scenario": "refresh-scenario"}},
	}
	runner := &AgentRuntime{Config: cfg}
	installTestDetection(t, runner)
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	norm := eventadapter.NewEventNormalizer(cfg.Agent.ID, cfg.Agent.HostID, eventadapter.EventNormalizerOptions{})
	first := appendEndpointEventForTest(t, runner, nil, norm, sensorEventEnvelope("file.write", 100, "/usr/bin/curl", "/dev/shm/x.sh", ""))
	updated := runner.activePolicy()
	updated.PolicyID = "no-payload-after-refresh"
	updated.Version = 2
	disabled := false
	updated.Detection.RuleOverrides = append(updated.Detection.RuleOverrides, policymodel.RuleOverride{RuleID: "payload_dropped", Enabled: &disabled})
	runner.applyRuntimePolicy(updated)
	second := appendEndpointEventForTest(t, runner, nil, norm, sensorEventEnvelope("file.write", 101, "/usr/bin/curl", "/dev/shm/x.sh", ""))
	signalCounts := []int{len(first.GetSignals()), len(second.GetSignals())}
	if !containsInt(signalCounts, 1) || !containsInt(signalCounts, 0) {
		t.Fatalf("signal counts = %v, want one pre-refresh signal and one post-refresh suppressed signal", signalCounts)
	}
	if runner.activePolicy().PolicyID != "no-payload-after-refresh" || runner.activePolicy().Version != 2 {
		t.Fatalf("active policy = %+v", runner.activePolicy())
	}
}
