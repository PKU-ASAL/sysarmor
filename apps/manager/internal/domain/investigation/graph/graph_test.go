package graph

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestFromEventsRecoversCausalPathAndEventRefs(t *testing.T) {
	events := causalEvents()
	value := FromEvents(events).ConnectingEvidence([]domaintelemetry.Signal{
		{Entities: []domaintelemetry.Entity{{Kind: "process", Key: "p-shell", Role: "subject"}}},
		{Entities: []domaintelemetry.Entity{{Kind: "file", Key: "/dev/shm/x.sh", Role: "object"}}},
		{Entities: []domaintelemetry.Entity{{Kind: "socket", Key: "10.66.0.99:443", Role: "object"}}},
	})
	for _, id := range []string{"process:p-shell", "process:p-curl", "file:/dev/shm/x.sh", "process:p-bash", "socket:10.66.0.99:443"} {
		if !hasNode(value.Nodes, id) {
			t.Fatalf("nodes = %+v, missing %q", value.Nodes, id)
		}
	}
	if len(value.Edges) != 4 {
		t.Fatalf("edges = %+v", value.Edges)
	}
	for _, eventID := range []string{"exec-curl", "write-payload", "exec-bash", "connect-c2"} {
		if !hasEventRef(value.Edges, eventID) {
			t.Fatalf("edges = %+v, missing event ref %q", value.Edges, eventID)
		}
	}
}

func TestFromEventsMarksUnavailableParentAsGap(t *testing.T) {
	value := FromEvents([]domaintelemetry.Event{{
		ID: "exec-bash", Behavior: "process.exec", IdentityStatus: "unavailable",
		SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-bash"},
	}}).ConnectingEvidence([]domaintelemetry.Signal{{Entities: []domaintelemetry.Entity{{Kind: "process", Key: "p-bash", Role: "subject"}}}})
	if !hasNode(value.Nodes, "gap:parent:exec-bash") || !hasIncompleteEdge(value.Edges, "gap:parent:exec-bash", "process:p-bash") {
		t.Fatalf("gap evidence = %+v", value)
	}
}

func TestFromEventsKeepsRootProcessAsSignalSeedWithoutGap(t *testing.T) {
	value := FromEvents([]domaintelemetry.Event{{
		ID: "exec-root", Behavior: "process.exec",
		SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-root"},
	}}).ConnectingEvidence([]domaintelemetry.Signal{{
		Entities: []domaintelemetry.Entity{{Kind: "process", Key: "p-root", Role: "subject"}},
	}})

	if !hasNode(value.Nodes, "process:p-root") {
		t.Fatalf("root process node missing: %+v", value.Nodes)
	}
	if hasNode(value.Nodes, "gap:seed:process:p-root") {
		t.Fatalf("root process was replaced by seed gap: %+v", value.Nodes)
	}
}

func TestFromEventsPreservesForkOperation(t *testing.T) {
	value := FromEvents([]domaintelemetry.Event{
		{
			ID: "fork-child", Behavior: "process.fork", ParentStableID: "p-parent",
			SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-child"},
		},
		{
			ID: "fork-orphan", Behavior: "process.fork", IdentityStatus: "unavailable",
			SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-orphan"},
		},
	}).EvidenceSubgraph()

	if !hasEdge(value.Edges, "process:p-parent", "process:p-child", "fork", "fork-child", false) {
		t.Fatalf("fork edge = %+v", value.Edges)
	}
	if !hasEdge(value.Edges, "gap:parent:fork-orphan", "process:p-orphan", "fork", "fork-orphan", true) {
		t.Fatalf("fork gap edge = %+v", value.Edges)
	}
}

func TestFromEventsUsesProvenanceDirectionAndAggregatesRepeatedEdges(t *testing.T) {
	process := &domaintelemetry.ProcessRef{StableID: "p-shell"}
	value := FromEvents([]domaintelemetry.Event{
		{ID: "read-1", Behavior: "file.read", SubjectProcess: process, Object: &domaintelemetry.ObjectRef{FilePath: "/tmp/input"}},
		{ID: "read-2", Behavior: "file.read", SubjectProcess: process, Object: &domaintelemetry.ObjectRef{FilePath: "/tmp/input"}},
		{ID: "exit-1", Behavior: "process.exit", SubjectProcess: process},
	}).EvidenceSubgraph()

	if len(value.Edges) != 1 || !hasEdge(value.Edges, "file:/tmp/input", "process:p-shell", "read", "read-1", false) || !hasEventRef(value.Edges, "read-2") {
		t.Fatalf("provenance edges = %+v", value.Edges)
	}
}

func TestConnectingEvidenceSelectsSeedsDeterministically(t *testing.T) {
	events := make([]domaintelemetry.Event, maxEvidenceSeeds+2)
	signals := make([]domaintelemetry.Signal, len(events))
	for index := range events {
		processID := fmt.Sprintf("process-%02d", index)
		events[index] = domaintelemetry.Event{
			ID: fmt.Sprintf("event-%02d", index), OccurredAtNS: uint64(index), Behavior: "process.exec",
			SubjectProcess: &domaintelemetry.ProcessRef{StableID: processID},
		}
		signals[index] = domaintelemetry.Signal{Entities: []domaintelemetry.Entity{{Kind: "process", Key: processID, Role: "subject"}}}
	}
	reversed := append([]domaintelemetry.Signal(nil), signals...)
	slices.Reverse(reversed)

	first := FromEvents(events).ConnectingEvidence(signals)
	second := FromEvents(events).ConnectingEvidence(reversed)

	if !reflect.DeepEqual(first, second) || len(first.Nodes) != maxEvidenceSeeds {
		t.Fatalf("first = %+v, second = %+v", first, second)
	}
}

func TestConnectingEvidenceKeepsAllSignalSeedsWithinBound(t *testing.T) {
	const seedCount = 64
	events := make([]domaintelemetry.Event, seedCount)
	signals := make([]domaintelemetry.Signal, seedCount)
	for index := range events {
		processID := fmt.Sprintf("process-%02d", index)
		events[index] = domaintelemetry.Event{
			ID: fmt.Sprintf("event-%02d", index), Behavior: "process.exec",
			OccurredAtNS: uint64(index), SubjectProcess: &domaintelemetry.ProcessRef{StableID: processID},
		}
		signals[index] = domaintelemetry.Signal{Entities: []domaintelemetry.Entity{{Kind: "process", Key: processID, Role: "subject"}}}
	}

	value := FromEvents(events).ConnectingEvidence(signals)
	if len(value.Nodes) != seedCount {
		t.Fatalf("nodes = %d, want %d", len(value.Nodes), seedCount)
	}
}

func causalEvents() []domaintelemetry.Event {
	return []domaintelemetry.Event{
		{ID: "exec-curl", Behavior: "process.exec", ParentStableID: "p-shell", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-curl"}},
		{ID: "write-payload", Behavior: "file.write", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-curl"}, Object: &domaintelemetry.ObjectRef{Kind: "file", FilePath: "/dev/shm/x.sh"}},
		{ID: "exec-bash", Behavior: "process.exec", ParentStableID: "p-curl", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-bash"}},
		{ID: "connect-c2", Behavior: "network.connect", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "p-bash"}, Object: &domaintelemetry.ObjectRef{Kind: "socket", SocketAddress: "10.66.0.99:443"}},
	}
}

func hasNode(nodes []domaintelemetry.GraphNode, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}

func hasEventRef(edges []domaintelemetry.GraphEdge, eventID string) bool {
	for _, edge := range edges {
		for _, ref := range edge.EventRefs {
			if ref == eventID {
				return true
			}
		}
	}
	return false
}

func hasIncompleteEdge(edges []domaintelemetry.GraphEdge, from, to string) bool {
	for _, edge := range edges {
		if edge.From == from && edge.To == to && edge.Incomplete {
			return true
		}
	}
	return false
}

func hasEdge(edges []domaintelemetry.GraphEdge, from, to, kind, eventID string, incomplete bool) bool {
	for _, edge := range edges {
		if edge.From == from && edge.To == to && edge.Kind == kind && edge.Incomplete == incomplete && slices.Contains(edge.EventRefs, eventID) {
			return true
		}
	}
	return false
}
