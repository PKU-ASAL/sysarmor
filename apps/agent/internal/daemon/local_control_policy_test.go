package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestLocalControlExplainCollectionPolicyDryRunDoesNotApply(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	sensor := &recordingCollectionSensor{healthOnlySensor: healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}}}
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}, ObserveOnly: true},
		},
		Sensor:     sensor,
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
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-explain"},
		PolicyType: "collection",
		DryRun:     true,
		PolicyJson: `{"policy_id":"collection-explain","version":1,"behaviors":[{"id":"process.exec"}],"observe_only":true}`,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy(collection dry-run) error = %v", err)
	}
	if ack.Status != "degraded" || ack.PolicyId != "collection-explain" {
		t.Fatalf("ack = %+v", ack)
	}
	if sensor.lastIntent.Behaviors != nil {
		t.Fatalf("dry-run applied sensor intent = %+v", sensor.lastIntent)
	}
	for _, want := range []string{`"behavior_mappings"`, `"detection_coverage"`, `"missing_behaviors"`} {
		if !strings.Contains(ack.ReportJson, want) {
			t.Fatalf("report_json missing %s: %s", want, ack.ReportJson)
		}
	}
}

func TestLocalControlApplyPolicyUpdatesCurrentPolicy(t *testing.T) {
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
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-a"},
		PolicyType: "endpoint",
		PolicyJson: `{
			"policy_id":"local-policy",
			"version":7,
			"collection":{"behaviors":["process.exec"]},
			"detection":{"policy_id":"local-detection","version":1,"rulesets":[{"ref":"ruleset:cep-endpoint","enabled":true}]},
			"telemetry":{"max_batch_items":256,"max_batch_bytes":262144,"flush_interval":"1s"},
			"response":{}
		}`,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy() error = %v", err)
	}
	if ack.Status != "degraded" || ack.PolicyId != "local-policy" || ack.PolicyVersion != 7 {
		t.Fatalf("ack = %+v", ack)
	}
	current, err := client.CurrentPolicy(context.Background(), &controlplanev1.CurrentPolicyRequest{})
	if err != nil {
		t.Fatalf("CurrentPolicy() error = %v", err)
	}
	if current.PolicyId != "local-policy" || current.RawJson == "" {
		t.Fatalf("current = %+v", current)
	}
}

func TestManagedAgentRejectsLocalEndpointPolicyMutation(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setManagedEnrollmentForTest(t, store)
	runner := &AgentRuntime{
		Config:     config.Config{Agent: config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "tenant-a"}},
		Sensor:     &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		capability: contract.Capability{Backend: "fake", SupportsExec: true}, localStore: store,
	}
	installTestDetection(t, runner)
	controller := newApplicationPolicyController(runner, sensorruntime.New(runner.Sensor), nil)
	result := controller.ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "endpoint", Source: agentcontrol.PolicySourceStandalone,
		Document: `{"policy_id":"local-policy","version":2,"collection":{"behaviors":["process.exec"]},"detection":{"policy_id":"local-detection","version":1,"rulesets":[{"ref":"ruleset:cep-endpoint","enabled":true}]},"telemetry":{"max_batch_items":64,"max_batch_bytes":65536,"flush_interval":"1s"},"response":{}}`,
	})
	if result.Status != "rejected" || !strings.Contains(result.Message, "managed policy authority") {
		t.Fatalf("result=%+v", result)
	}
}

func TestManagedAgentRejectsLocalContentMutation(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setManagedEnrollmentForTest(t, store)
	runner := &AgentRuntime{Config: config.Config{Agent: config.AgentConfig{ID: "agent-a", TenantID: "tenant-a"}}, localStore: store}
	result := agentcontrol.NewContentController(newContentApplicationAdapter(runner)).ApplyContent(t.Context(), agentcontrol.ContentCommand{
		Document: "{}", AllowUnsigned: true, Source: agentcontrol.PolicySourceStandalone,
	})
	if result.Status != "rejected" || !strings.Contains(result.Message, "managed policy authority") {
		t.Fatalf("result=%+v", result)
	}
}

func TestManagedTransitionWaitsForLocalPolicyMutation(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &AgentRuntime{localStore: store}
	release, err := runner.beginLocalPolicyMutation(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	transitioned := make(chan struct{})
	go func() {
		runner.policyAuthorityMu.Lock()
		close(transitioned)
		runner.policyAuthorityMu.Unlock()
	}()
	select {
	case <-transitioned:
		t.Fatal("managed transition entered during local mutation")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case <-transitioned:
	case <-time.After(time.Second):
		t.Fatal("managed transition remained blocked after local mutation")
	}
}

func TestEnrollingAgentRejectsLocalPolicyMutation(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SetEnrolling(t.Context(), testRemoteEnrollment()); err != nil {
		t.Fatal(err)
	}
	runner := &AgentRuntime{localStore: store}

	release, err := runner.beginLocalPolicyMutation(t.Context(), true)

	if err == nil || release != nil || !strings.Contains(err.Error(), "managed policy authority") {
		t.Fatalf("release_present=%t error=%v", release != nil, err)
	}
}

func TestLocalPolicyMutationFailsClosedWithoutStore(t *testing.T) {
	runner := &AgentRuntime{}

	release, err := runner.beginLocalPolicyMutation(t.Context(), true)

	if err == nil || release != nil || !strings.Contains(err.Error(), "local store is unavailable") {
		t.Fatalf("release_present=%t error=%v", release != nil, err)
	}
	readRelease, err := runner.beginLocalPolicyMutation(t.Context(), false)
	if err != nil || readRelease == nil {
		t.Fatalf("read-only release_present=%t error=%v", readRelease != nil, err)
	}
	readRelease()
}

func TestLocalControlApplyTelemetryPolicyContract(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:     config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control:   config.ControlConfig{SocketPath: socketPath},
			Manager:   config.ManagerConfig{Address: "127.0.0.1:9443", Transport: "grpc"},
			Telemetry: config.TelemetryConfig{MaxBatchItems: 10, MaxBatchBytes: 256 << 10, FlushInterval: time.Second},
			Local:     config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: time.Second, RetryMax: 30 * time.Second, RequestTimeout: 10 * time.Second, MaxInflight: 1}},
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
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-telemetry"},
		PolicyType: "telemetry",
		Telemetry: &controlplanev1.TelemetryPolicy{
			MaxBatchItems: 64,
			MaxBatchBytes: 131072,
			FlushInterval: "2s",
		},
	})
	if err != nil {
		t.Fatalf("ApplyPolicy(telemetry) error = %v", err)
	}
	if ack.Status != "applied" || len(ack.Sections) != 1 || ack.Sections[0].RequiresRestart {
		t.Fatalf("ack = %+v", ack)
	}
	if runner.Config.Manager.Transport != "grpc" || runner.Config.Manager.Address != "127.0.0.1:9443" {
		t.Fatalf("manager config = %+v", runner.Config.Manager)
	}
	effective := runner.currentEffectiveTelemetry()
	if effective.MaxBatchItems != 64 || effective.MaxBatchBytes != 131072 || effective.FlushInterval != 2*time.Second {
		t.Fatalf("effective telemetry = %+v", effective)
	}
	if runner.Config.Telemetry.MaxBatchItems != 10 {
		t.Fatalf("telemetry config baseline was mutated: %+v", runner.Config.Telemetry)
	}
	if runner.Config.Local.Export.RetryInitial != time.Second || runner.Config.Local.Export.RetryMax != 30*time.Second || runner.Config.Local.Export.RequestTimeout != 10*time.Second || runner.Config.Local.Export.MaxInflight != 1 {
		t.Fatalf("export config changed by telemetry policy: %+v", runner.Config.Local.Export)
	}
}

func TestApplyTelemetryPolicyPersistsUnifiedEndpointPolicy(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &AgentRuntime{localStore: store, Config: config.Config{Telemetry: config.TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second}}}
	runner.setEndpointPolicy(agentpolicy.EndpointPolicy{PolicyID: "endpoint-a", Version: 1})
	result := newApplicationPolicyController(runner, nil, nil).ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "telemetry", Source: agentcontrol.PolicySourceStandalone,
		Document: `{"max_batch_items":512,"max_batch_bytes":524288,"flush_interval":"2s"}`,
	})
	if result.Status != "applied" {
		t.Fatalf("result=%+v", result)
	}
	record, ok, err := store.Policy(t.Context(), "endpoint")
	if err != nil || !ok {
		t.Fatalf("policy ok=%t err=%v", ok, err)
	}
	var persisted agentpolicy.EndpointPolicy
	if err := json.Unmarshal(record.Document, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Telemetry.MaxBatchItems != 512 || persisted.Version != 2 {
		t.Fatalf("persisted=%+v", persisted.Telemetry)
	}
}

func TestLocalControlApplyCollectionPolicyUpdatesSensorRuntime(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	sensor := &recordingCollectionSensor{healthOnlySensor: healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}}}
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}, ObserveOnly: true},
		},
		Sensor:     sensor,
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
	for _, contentJSON := range []string{
		`{
			"api_version":"sysarmor.content/v1",
			"kind":"contextset",
			"metadata":{"id":"ctx:payload-path-prefixes","version":"2026.06.18.1"},
			"spec":{"value_type":"path_prefix","values":["/dev/shm"]}
		}`,
		`{
			"api_version":"sysarmor.content/v1",
			"kind":"iocpack",
			"metadata":{"id":"ioc:c2-ip-feed","version":"2026.06.18.1"},
			"spec":{"value_type":"ip","values":["10.66.0.99"]}
		}`,
		`{
			"api_version":"sysarmor.content/v1",
			"kind":"iocpack",
			"metadata":{"id":"ioc:c2-control-port-feed","version":"2026.06.18.1"},
			"spec":{"value_type":"port","values":["443"]}
		}`,
	} {
		if _, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
			Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-content"},
			ContentJson:   contentJSON,
			AllowUnsigned: true,
		}); err != nil {
			t.Fatalf("ApplyContent() error = %v", err)
		}
	}
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context: &controlplanev1.RequestContext{
			TenantId: "default", AgentId: "agent-a", RequestId: "req-collection",
			Scope: &controlplanev1.Scope{Type: "container", Selector: "container-a"},
		},
		PolicyType: "collection",
		PolicyJson: `{
			"policy_id":"collection-a",
			"version":3,
			"behaviors":[
				{"id":"network.connect","selectors":{"socket":{"families":["AF_INET"],"addr_refs":["ioc:c2-ip-feed"],"port_refs":["ioc:c2-control-port-feed"]}}},
				{"id":"file.write","selectors":{"file":{"prefix_refs":["ctx:payload-path-prefixes"]}}}
			],
			"observe_only":true
		}`,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy(collection) error = %v", err)
	}
	if ack.Status != "degraded" || ack.PolicyId != "collection-a" || ack.PolicyVersion != 3 {
		t.Fatalf("ack = %+v", ack)
	}
	if ack.ReportJson == "" || !strings.Contains(ack.ReportJson, `"pushed_down_selectors"`) || !strings.Contains(ack.ReportJson, `"generated_policy_hash"`) {
		t.Fatalf("ack report_json = %q", ack.ReportJson)
	}
	if !strings.Contains(ack.ReportJson, `"resolved_refs"`) || !strings.Contains(ack.ReportJson, `"ioc:c2-ip-feed"`) || !strings.Contains(ack.ReportJson, `"ctx:payload-path-prefixes"`) {
		t.Fatalf("ack report_json = %q", ack.ReportJson)
	}
	if !containsString(ack.Details, "unsupported_selectors=0") {
		t.Fatalf("ack details = %v", ack.Details)
	}
	if !containsString(ack.Details, "resolved_refs=3") {
		t.Fatalf("ack details = %v", ack.Details)
	}
	got := sensor.lastIntent
	if got.ScopeType != "container" || got.ScopeSelector != "container-a" {
		t.Fatalf("intent scope = %q/%q", got.ScopeType, got.ScopeSelector)
	}
	if len(got.Behaviors) != 2 || got.Behaviors[0] != "network.connect" {
		t.Fatalf("intent behaviors = %v", got.Behaviors)
	}
	if len(got.BehaviorFilters) != 2 {
		t.Fatalf("intent behavior filters = %+v", got.BehaviorFilters)
	}
	if got.BehaviorFilters[0].Behavior != "network.connect" || got.BehaviorFilters[0].SocketFamilies[0] != "AF_INET" {
		t.Fatalf("network filter = %+v", got.BehaviorFilters[0])
	}
	if got.BehaviorFilters[1].Behavior != "file.write" || got.BehaviorFilters[1].FilePrefixes[0] != "/dev/shm" {
		t.Fatalf("file filter = %+v", got.BehaviorFilters[1])
	}
}

func TestLocalControlPushesNetworkProcessBinarySelector(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	sensor := &recordingCollectionSensor{healthOnlySensor: healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}}}
	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}, ObserveOnly: true},
		},
		Sensor:     sensor,
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
	ack, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a", RequestId: "req-network-binary"},
		PolicyType: "collection",
		PolicyJson: `{
			"policy_id":"collection-network-binary",
			"version":1,
			"behaviors":[
				{"id":"network.connect","selectors":{"process":{"binary_prefixes":["/tmp"]},"socket":{"families":["AF_INET"]}}}
			],
			"observe_only":true
		}`,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy(collection) error = %v", err)
	}
	if ack.Status != "degraded" {
		t.Fatalf("ack status = %q, want degraded from detection dependencies: %+v", ack.Status, ack)
	}
	if strings.Contains(ack.ReportJson, `"unsupported_selectors"`) || !strings.Contains(ack.ReportJson, `"process.binary_prefix"`) || !strings.Contains(ack.ReportJson, `"pushed_down"`) {
		t.Fatalf("ack report_json = %q", ack.ReportJson)
	}
	if len(sensor.lastIntent.Behaviors) != 1 || sensor.lastIntent.BehaviorFilters[0].BinaryPrefixes[0] != "/tmp" {
		t.Fatalf("sensor intent = %+v", sensor.lastIntent)
	}
}
