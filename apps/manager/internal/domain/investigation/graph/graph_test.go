package graph

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestFromSignalsBuildsSubjectEdges(t *testing.T) {
	value := FromSignals([]domaintelemetry.Signal{{Name: "reverse_shell_pattern", Entities: []domaintelemetry.Entity{
		{Kind: "process", Key: "p-bash", Role: "subject"},
		{Kind: "socket", Key: "10.66.0.99:443", Role: "object"},
	}}}).EvidenceSubgraph()
	if !hasNode(value.Nodes, "process:p-bash") || !hasNode(value.Nodes, "socket:10.66.0.99:443") {
		t.Fatalf("nodes = %+v", value.Nodes)
	}
	if !hasEdge(value.Edges, "process:p-bash", "socket:10.66.0.99:443", "connect") {
		t.Fatalf("edges = %+v", value.Edges)
	}
}

func TestShortestPathReturnsOnlyConnectingPath(t *testing.T) {
	value := FromSignals([]domaintelemetry.Signal{
		{Name: "payload_dropped", Entities: entities("p-curl", "file", "/dev/shm/x.sh")},
		{Name: "reverse_shell_pattern", Entities: entities("p-curl", "socket", "10.66.0.99:443")},
	}).ShortestPath("file:/dev/shm/x.sh", "socket:10.66.0.99:443")
	if len(value.Nodes) != 3 || len(value.Edges) != 2 {
		t.Fatalf("subgraph = %+v", value)
	}
}

func TestKHopReturnsNeighborhood(t *testing.T) {
	value := FromSignals([]domaintelemetry.Signal{
		{Name: "payload_dropped", Entities: entities("p-curl", "file", "/dev/shm/x.sh")},
		{Name: "reverse_shell_pattern", Entities: entities("p-curl", "socket", "10.66.0.99:443")},
	}).KHop("process:p-curl", 1)
	if len(value.Nodes) != 3 || len(value.Edges) != 2 {
		t.Fatalf("subgraph = %+v", value)
	}
}

func entities(processKey, objectKind, objectKey string) []domaintelemetry.Entity {
	return []domaintelemetry.Entity{
		{Kind: "process", Key: processKey, Role: "subject"},
		{Kind: objectKind, Key: objectKey, Role: "object"},
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

func hasEdge(edges []domaintelemetry.GraphEdge, from, to, kind string) bool {
	for _, edge := range edges {
		if edge.From == from && edge.To == to && edge.Kind == kind {
			return true
		}
	}
	return false
}
