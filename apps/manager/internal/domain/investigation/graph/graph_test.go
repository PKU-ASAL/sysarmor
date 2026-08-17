package graph

import (
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
