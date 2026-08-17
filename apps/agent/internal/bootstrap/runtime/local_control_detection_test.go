package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestLocalControlContentApplyEnablesCEPRulePack(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	runner := &Coordinator{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "default"},
			Control: config.ControlConfig{SocketPath: socketPath},
			Sensor:  config.SensorConfig{Scope: config.RuntimeScope{Type: "host"}},
		},
		Sensor:      &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, Installed: true, PolicyLoaded: true}},
		sensorState: sensorRuntime{capability: contract.Capability{Backend: "fake", SupportsExec: true, SupportsFile: true, SupportsConnect: true}},
	}
	rt := sensorruntime.New(runner.Sensor)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus, batcher, sender := newTestTelemetry(t, runner)
	stop, err := startTestLocalControlServer(runner, ctx, rt, bus, batcher, sender, time.Now())
	if err != nil {
		t.Fatalf("startLocalControlServer() error = %v", err)
	}
	defer stop()

	client := newUnixControlClient(t, socketPath)
	contentAck, err := client.ApplyContent(context.Background(), &controlplanev1.ApplyContentRequest{
		Context:       &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"},
		ContentJson:   cepRulePackJSON(),
		AllowUnsigned: true,
	})
	if err != nil {
		t.Fatalf("ApplyContent() error = %v", err)
	}
	if contentAck.GetStatus() != "applied" {
		t.Fatalf("content ack = %+v", contentAck)
	}
	detectionPolicy := `{
		"policy_id":"local-cep-detection",
		"version":1,
		"mode":"observe",
		"rulesets":[{"ref":"ruleset:cep","enabled":true}]
	}`
	policyAck, err := client.ApplyPolicy(context.Background(), &controlplanev1.ApplyPolicyRequest{
		Context:    &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"},
		PolicyType: "detection",
		PolicyJson: detectionPolicy,
	})
	if err != nil {
		t.Fatalf("ApplyPolicy() error = %v", err)
	}
	if policyAck.GetStatus() != "applied" {
		t.Fatalf("policy ack = %+v", policyAck)
	}

	norm := newTestEventNormalizer(t, runner, "agent-a", "host-a", eventadapter.EventNormalizerOptions{TenantID: "default", ScopeType: "host"})
	for _, ev := range []contract.EventEnvelope{
		cepSensorEventEnvelope("file.write", "/usr/bin/curl", "/dev/shm/cep-x", ""),
		cepSensorEventEnvelope("file.chmod", "/usr/bin/chmod", "/dev/shm/cep-x", ""),
		cepSensorEventEnvelope("process.exec", "/dev/shm/cep-x", "", ""),
		cepSensorEventEnvelope("network.connect", "/dev/shm/cep-x", "", "10.66.0.99:443"),
	} {
		appendEndpointEventForTest(t, runner, bus, norm, ev)
	}

	signalStream, err := client.WatchSignals(context.Background(), &controlplanev1.WatchSignalsRequest{IncludeRecent: true, Limit: 1, RuleId: "cep_payload_lifecycle", Where: "endpoint"})
	if err != nil {
		t.Fatalf("WatchSignals() error = %v", err)
	}
	frame, err := signalStream.Recv()
	if err != nil {
		t.Fatalf("signal Recv() error = %v", err)
	}
	if got := frame.GetSignal().GetEventRefs(); len(got) != 4 {
		t.Fatalf("event refs = %v, want 4", got)
	}
	if frame.GetSignal().GetStage() != signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE ||
		frame.GetSignal().GetDetectorKind() != signalv1.DetectorKind_DETECTOR_KIND_RULE {
		t.Fatalf("signal = %+v, want rule candidate", frame.GetSignal())
	}
	health, err := client.Health(context.Background(), &controlplanev1.HealthRequest{Context: &controlplanev1.RequestContext{TenantId: "default", AgentId: "agent-a"}})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.GetCep().GetEmittedSignals() == 0 {
		t.Fatalf("cep health = %+v, want emitted signals", health.GetCep())
	}
}

func cepSensorEventEnvelope(behavior, binary, filePath, dst string) contract.EventEnvelope {
	return contract.EventEnvelope{
		SensorEvent: &sensorv1.SensorEvent{
			Behavior: behavior,
			Proc: &sensorv1.RawProcess{
				Pid:          200,
				Binary:       binary,
				StartTimeNs:  200,
				SensorExecId: "cep-exec",
			},
			Object: &sensorv1.RawObject{
				Path: filePath,
				Dst:  dst,
			},
			RawRef: "cep-test-event",
		},
		RawRef: "cep-test-event",
	}
}

func cepRulePackJSON() string {
	return `{
		"api_version":"sysarmor.content/v1",
		"kind":"rulepack",
		"metadata":{"id":"rulepack:cep","version":"v1"},
		"spec":{"rulesets":[{"id":"ruleset:cep","version":"v1","rules":[{
			"rule_id":"cep_payload_lifecycle",
			"version":1,
			"severity":"critical",
			"runtime":{
				"type":"sequence",
				"sequence":{
					"within":"60s",
					"by":["lineage_id"],
					"steps":[
						{"id":"drop","event":"file.write","conditions":[{"field":"file.path","op":"prefix","value":"/dev/shm/"}]},
						{"id":"chmod","event":"file.chmod","conditions":[{"field":"file.path","op":"same_as","step":"drop"}]},
						{"id":"exec","event":"process.exec","conditions":[{"field":"process.binary","op":"same_as","step":"drop","step_field":"file.path"}]},
						{"id":"connect","event":"network.connect","conditions":[{"field":"socket.port","op":"in","values":["443"]}]}
					]
				}
			},
			"requires":{"events":[
				{"behavior":"file.write","fields":["file.path","process.binary","lineage_id"]},
				{"behavior":"file.chmod","fields":["file.path","lineage_id"]},
				{"behavior":"process.exec","fields":["process.binary","lineage_id"]},
				{"behavior":"network.connect","fields":["socket.port","lineage_id"]}
			]},
			"output":{"stage":"candidate"}
		}]}]}
	}`
}
