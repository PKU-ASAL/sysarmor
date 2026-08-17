package contracts

import (
	"math"
	"strings"
	"testing"

	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/proto"
)

func TestCanonicalEventRoundTrip(t *testing.T) {
	wire := &eventv1.CanonicalEvent{
		Id: "event-a", Seq: 7, AgentId: "agent-a", HostId: "host-a", MonoNs: 11,
		SubjectProc:    &eventv1.ProcessRef{StableId: "p-a", Pid: 42, Binary: "/bin/sh", Argv: []string{"sh", "-c"}, Uid: 1000, StartTimeNs: 9, ArgvBoundariesTrusted: true},
		Object:         &eventv1.ObjectRef{Kind: "file", FilePath: "/tmp/a", SocketAddr: "127.0.0.1:80", TargetProcStableId: "p-b"},
		ParentStableId: "p-parent", LineageId: "lin-a", RawRef: "raw-a", TenantId: "tenant-a",
		Scope: &eventv1.RuntimeScope{Type: "container", Selector: "checkout"}, ContainerId: "container-a",
		Cgroup: "cg-a", Namespace: "prod", Pod: "checkout-1", OccurredAtNs: 17, Behavior: "process.exec",
		Labels: map[string]string{"scenario": "one"},
	}
	domain, err := EventToDomain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := EventFromDomain(domain); !proto.Equal(got, wire) {
		t.Fatalf("round trip = %v, want %v", got, wire)
	}
}

func TestSignalRoundTrip(t *testing.T) {
	for _, where := range []signalv1.SignalWhere{
		signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		signalv1.SignalWhere_SIGNAL_WHERE_CLOUD,
	} {
		wire := fullSignal()
		wire.Where = where
		domain, err := SignalToDomain(wire)
		if err != nil {
			t.Fatal(err)
		}
		if got := SignalFromDomain(domain); !proto.Equal(got, wire) {
			t.Fatalf("round trip = %v, want %v", got, wire)
		}
	}
}

func TestIncidentRoundTrip(t *testing.T) {
	wire := &incidentv1.Incident{
		Id: "inc-a", Summary: "summary", Severity: 80, Mitre: []string{"T1059"}, LineageIds: []string{"lin-a"},
		ConclusionEntities: []string{"process:p-a"}, Labels: map[string]string{"scenario": "one"}, TenantId: "tenant-a",
		CorrelationKey: "corr-a", AnalysisVersion: "v1", FirstObservedAt: "first", LastObservedAt: "last",
		Evidence: &incidentv1.EvidenceSubgraph{
			Nodes: []*incidentv1.GraphNode{{Id: "process:p-a", Kind: "process", Label: "p-a", Entities: []*signalv1.EntityRef{{Kind: "process", Key: "process:p-a"}}}},
			Edges: []*incidentv1.GraphEdge{{Id: "exec:a->b", From: "a", To: "b", Kind: "exec"}},
		},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity", SeedIds: []string{"a"}, PathIds: []string{"b"}, Score: 80, Controls: []string{"conclusion"}},
		ContributingSignals: []*signalv1.Signal{modelSignal(), fullSignal()},
	}
	domain, err := IncidentToDomain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := IncidentFromDomain(domain); !proto.Equal(got, wire) {
		t.Fatalf("round trip = %v, want %v", got, wire)
	}
}

func TestSignalToDomainRejectsUnspecifiedClassification(t *testing.T) {
	tests := []struct {
		name   string
		signal *signalv1.Signal
	}{
		{name: "where", signal: &signalv1.Signal{Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE}},
		{name: "stage", signal: &signalv1.Signal{Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE}},
		{name: "detector kind", signal: &signalv1.Signal{Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SignalToDomain(test.signal); err == nil {
				t.Fatal("unspecified signal classification accepted")
			}
		})
	}
}

func TestSignalToDomainRejectsInvalidModelSemantics(t *testing.T) {
	valid := modelSignal()
	tests := []struct {
		name   string
		mutate func(*signalv1.Signal)
	}{
		{name: "conclusion", mutate: func(signal *signalv1.Signal) { signal.Stage = signalv1.SignalStage_SIGNAL_STAGE_CONCLUSION }},
		{name: "missing provenance", mutate: func(signal *signalv1.Signal) { signal.ModelDigest = "" }},
		{name: "rule provenance", mutate: func(signal *signalv1.Signal) { signal.RuleId = "rule-a" }},
		{name: "response intent", mutate: func(signal *signalv1.Signal) {
			signal.ResponseIntent = &signalv1.ResponseIntent{ResponseIntent: "contain"}
		}},
		{name: "global rarity", mutate: func(signal *signalv1.Signal) { signal.GlobalRarity = 2 }},
		{name: "malformed digest", mutate: func(signal *signalv1.Signal) { signal.ModelDigest = "sha256:not-a-digest" }},
		{name: "unsupported schema", mutate: func(signal *signalv1.Signal) { signal.FeatureSchema = "unsupported-schema" }},
		{name: "non-finite score", mutate: func(signal *signalv1.Signal) { signal.LocalRarity = float32(math.Inf(1)) }},
		{name: "non-endpoint", mutate: func(signal *signalv1.Signal) { signal.Where = signalv1.SignalWhere_SIGNAL_WHERE_CLOUD }},
		{name: "missing event ref", mutate: func(signal *signalv1.Signal) { signal.EventRefs = nil }},
		{name: "blank event ref", mutate: func(signal *signalv1.Signal) { signal.EventRefs = []string{" "} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signal := proto.Clone(valid).(*signalv1.Signal)
			test.mutate(signal)
			if _, err := SignalToDomain(signal); err == nil {
				t.Fatal("invalid model detector output accepted")
			}
		})
	}
}

func TestSignalToDomainAcceptsFiniteNegativeModelAnomalyScore(t *testing.T) {
	signal := modelSignal()
	signal.LocalRarity = -1
	if _, err := SignalToDomain(signal); err != nil {
		t.Fatalf("finite negative AS rejected: %v", err)
	}
}

func TestSignalToDomainNamesRejectedModelConclusionPrecisely(t *testing.T) {
	signal := modelSignal()
	signal.Stage = signalv1.SignalStage_SIGNAL_STAGE_CONCLUSION
	_, err := SignalToDomain(signal)
	if err == nil || err.Error() != "model detector output must be a candidate" {
		t.Fatalf("error = %v", err)
	}
}

func TestSignalToDomainRejectsUnknownClassification(t *testing.T) {
	if _, err := SignalToDomain(&signalv1.Signal{Where: signalv1.SignalWhere(99), Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE}); err == nil {
		t.Fatal("unknown signal where accepted")
	}
	if _, err := SignalToDomain(&signalv1.Signal{Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, Stage: signalv1.SignalStage(99), DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE}); err == nil {
		t.Fatal("unknown signal stage accepted")
	}
	if _, err := SignalToDomain(&signalv1.Signal{Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind(99)}); err == nil {
		t.Fatal("unknown detector kind accepted")
	}
}

func TestIncidentToDomainRequiresConclusion(t *testing.T) {
	tests := []struct {
		name    string
		signals []*signalv1.Signal
	}{
		{name: "empty"},
		{name: "candidate only", signals: []*signalv1.Signal{{
			Id: "candidate-a", Where: signalv1.SignalWhere_SIGNAL_WHERE_CLOUD,
			Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE,
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := IncidentToDomain(&incidentv1.Incident{ContributingSignals: test.signals}); err == nil {
				t.Fatal("incident without a conclusion accepted")
			}
		})
	}
}

func TestWireToDomainRejectsNilMessages(t *testing.T) {
	if _, err := EventToDomain(nil); err == nil {
		t.Fatal("nil event accepted")
	}
	if _, err := SignalToDomain(nil); err == nil {
		t.Fatal("nil signal accepted")
	}
	if _, err := IncidentToDomain(nil); err == nil {
		t.Fatal("nil incident accepted")
	}
	if _, err := IncidentToDomain(&incidentv1.Incident{ContributingSignals: []*signalv1.Signal{nil}}); err == nil {
		t.Fatal("nil contributing signal accepted")
	}
}

func fullSignal() *signalv1.Signal {
	return &signalv1.Signal{
		Id: "signal-a", Name: "reverse_shell_pattern", Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		Stage: signalv1.SignalStage_SIGNAL_STAGE_CONCLUSION, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE,
		BaseRisk: 80, LocalRarity: 0.5, GlobalRarity: 0.25, LineageId: "lin-a",
		Entities:  []*signalv1.EntityRef{{Kind: "process", Key: "process:p-a", Role: "subject"}},
		EventRefs: []string{"event-a"}, SignalRefs: []string{"signal-parent"}, CrossLineage: true,
		Evidence:       &signalv1.EvidenceBundle{Id: "ev-a", EventRefs: []string{"event-a"}, RawRefs: []string{"raw-a"}, Entities: []*signalv1.EntityRef{{Kind: "file", Key: "file:/tmp/a"}}, Summary: "evidence"},
		ResponseIntent: &signalv1.ResponseIntent{ResponseIntent: "contain", RecommendedAction: "kill", Confidence: 90, Reason: "reason"},
		RuleId:         "rule-a", RuleVersion: 2, RulesetRef: "ruleset:a",
		ContextRefs: []*signalv1.ContentRef{{Ref: "context-a", Version: "1", Digest: "sha256:a"}},
		IocRefs:     []*signalv1.ContentRef{{Ref: "ioc-a", Version: "1", Digest: "sha256:b"}},
		Severity:    "high", Confidence: 88, Mode: "observe", Labels: map[string]string{"scenario": "one"},
	}
}

func modelSignal() *signalv1.Signal {
	return &signalv1.Signal{
		Id: "model-a", Name: "model_anomaly", Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_MODEL,
		ModelRef: "model:profile-v2", ModelVersion: "2", ModelDigest: "sha256:" + strings.Repeat("a", 64), FeatureSchema: "FeatureSchemaV2",
		LocalRarity: 4, EventRefs: []string{"event-a"}, Mode: "shadow",
	}
}
