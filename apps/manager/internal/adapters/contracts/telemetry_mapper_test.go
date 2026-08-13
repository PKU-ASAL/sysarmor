package contracts

import (
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
	wire := fullSignal()
	domain, err := SignalToDomain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := SignalFromDomain(domain); !proto.Equal(got, wire) {
		t.Fatalf("round trip = %v, want %v", got, wire)
	}
}

func TestIncidentRoundTrip(t *testing.T) {
	wire := &incidentv1.Incident{
		Id: "inc-a", Summary: "summary", Severity: 80, Mitre: []string{"T1059"}, LineageIds: []string{"lin-a"},
		Terminals: []string{"process:p-a"}, Labels: map[string]string{"scenario": "one"}, TenantId: "tenant-a",
		CorrelationKey: "corr-a", AnalysisVersion: "v1", FirstObservedAt: "first", LastObservedAt: "last",
		Evidence: &incidentv1.EvidenceSubgraph{
			Nodes: []*incidentv1.GraphNode{{Id: "process:p-a", Kind: "process", Label: "p-a", Entities: []*signalv1.EntityRef{{Kind: "process", Key: "process:p-a"}}}},
			Edges: []*incidentv1.GraphEdge{{Id: "exec:a->b", From: "a", To: "b", Kind: "exec"}},
		},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity", SeedIds: []string{"a"}, PathIds: []string{"b"}, Score: 80, Controls: []string{"terminal"}},
		ContributingSignals: []*signalv1.Signal{fullSignal()},
	}
	domain, err := IncidentToDomain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := IncidentFromDomain(domain); !proto.Equal(got, wire) {
		t.Fatalf("round trip = %v, want %v", got, wire)
	}
}

func TestUnknownSignalWhereRoundTrip(t *testing.T) {
	wire := &signalv1.Signal{Id: "signal-a", Where: signalv1.SignalWhere(99)}
	domain, err := SignalToDomain(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got := SignalFromDomain(domain); !proto.Equal(got, wire) {
		t.Fatalf("round trip = %v, want %v", got, wire)
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
		BaseRisk: 80, LocalRarity: 0.5, GlobalRarity: 0.25, LineageId: "lin-a",
		Entities:  []*signalv1.EntityRef{{Kind: "process", Key: "process:p-a", Role: "subject"}},
		EventRefs: []string{"event-a"}, SignalRefs: []string{"signal-parent"}, Terminal: true, CrossLineage: true,
		Evidence:       &signalv1.EvidenceBundle{Id: "ev-a", EventRefs: []string{"event-a"}, RawRefs: []string{"raw-a"}, Entities: []*signalv1.EntityRef{{Kind: "file", Key: "file:/tmp/a"}}, Summary: "evidence"},
		ResponseIntent: &signalv1.ResponseIntent{ResponseIntent: "contain", RecommendedAction: "kill", Confidence: 90, Reason: "reason"},
		RuleId:         "rule-a", RuleVersion: 2, RulesetRef: "ruleset:a",
		ContextRefs: []*signalv1.ContentRef{{Ref: "context-a", Version: "1", Digest: "sha256:a"}},
		IocRefs:     []*signalv1.ContentRef{{Ref: "ioc-a", Version: "1", Digest: "sha256:b"}},
		Severity:    "high", Confidence: 88, Mode: "observe", Labels: map[string]string{"scenario": "one"},
	}
}
