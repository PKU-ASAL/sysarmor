package graph

import (
	"sort"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/entity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

const (
	maxEvidenceSeeds = 32
	maxGraphEvents   = 100_000
)

func FromEvents(events []domaintelemetry.Event) *Graph {
	value := New()
	for _, event := range orderedEvents(events) {
		value.AddEvent(event)
	}
	return value
}

func orderedEvents(events []domaintelemetry.Event) []domaintelemetry.Event {
	ordered := append([]domaintelemetry.Event(nil), events...)
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].OccurredAtNS != ordered[right].OccurredAtNS {
			return ordered[left].OccurredAtNS < ordered[right].OccurredAtNS
		}
		return ordered[left].ID < ordered[right].ID
	})
	if len(ordered) > maxGraphEvents {
		ordered = ordered[len(ordered)-maxGraphEvents:]
	}
	return ordered
}

func (value *Graph) AddEvent(event domaintelemetry.Event) {
	if value == nil || event.SubjectProcess == nil || event.SubjectProcess.StableID == "" {
		return
	}
	subject := entityID("process", event.SubjectProcess.StableID)
	value.addNode(domaintelemetry.Entity{Kind: "process", Key: subject, Role: "subject"})
	behavior := strings.ToLower(strings.TrimSpace(event.Behavior))
	switch behavior {
	case "process.exec", "process.fork":
		value.addProcessEvent(event, subject, strings.TrimPrefix(behavior, "process."))
	case "file.open", "file.read", "file.write", "file.chmod":
		if event.Object != nil {
			value.addObjectEvent(event, subject, event.Object.FilePath, "file", strings.TrimPrefix(event.Behavior, "file."))
		}
	case "network.connect":
		if event.Object != nil {
			value.addObjectEvent(event, subject, event.Object.SocketAddress, "socket", "connect")
		}
	}
}

func (value *Graph) ConnectingEvidence(signals []domaintelemetry.Signal) domaintelemetry.EvidenceSubgraph {
	seeds := value.addSignalSeeds(signals)
	if len(seeds) == 0 {
		return domaintelemetry.EvidenceSubgraph{}
	}
	nodes := make(map[string]bool, len(seeds))
	edges := make(map[string]bool)
	for _, seed := range seeds {
		nodes[seed] = true
	}
	if len(seeds) == 1 {
		mergeSubgraph(value.KHop(seeds[0], 1), nodes, edges)
	}
	for left := 0; left < len(seeds); left++ {
		for right := left + 1; right < len(seeds); right++ {
			mergeSubgraph(value.ShortestPath(seeds[left], seeds[right]), nodes, edges)
		}
	}
	value.includeAdjacentGaps(nodes, edges)
	return value.subgraph(nodes, edges)
}

func (value *Graph) includeAdjacentGaps(nodes, edges map[string]bool) {
	for _, edgeID := range value.edgeOrder {
		edge := value.edges[edgeID]
		if edge.Incomplete && (nodes[edge.From] || nodes[edge.To]) {
			nodes[edge.From], nodes[edge.To], edges[edgeID] = true, true, true
		}
	}
}

func (value *Graph) addProcessEvent(event domaintelemetry.Event, subject, relation string) {
	if event.ParentStableID != "" {
		parent := entityID("process", event.ParentStableID)
		value.addNode(domaintelemetry.Entity{Kind: "process", Key: parent, Role: "parent"})
		value.addEventEdge(parent, subject, relation, event.ID, false)
		return
	}
	if event.IdentityStatus == "unavailable" {
		gap := "gap:parent:" + event.ID
		value.addRawNode(gap, "gap")
		value.addEventEdge(gap, subject, relation, event.ID, true)
	}
}

func (value *Graph) addObjectEvent(event domaintelemetry.Event, subject, key, kind, relation string) {
	if event.Object == nil || strings.TrimSpace(key) == "" {
		return
	}
	object := entityID(kind, key)
	value.addNode(domaintelemetry.Entity{Kind: kind, Key: object, Role: "object"})
	value.addEventEdge(subject, object, relation, event.ID, false)
}

func (value *Graph) addSignalSeeds(signals []domaintelemetry.Signal) []string {
	entities := make(map[string]domaintelemetry.Entity)
	for _, signal := range signals {
		for _, current := range entity.Unique(signal.Entities) {
			entities[current.Key] = current
		}
	}
	keys := make([]string, 0, len(entities))
	for key := range entities {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > maxEvidenceSeeds {
		keys = keys[:maxEvidenceSeeds]
	}
	seeds := make([]string, 0, len(keys))
	for _, key := range keys {
		if value.hasNode(key) {
			seeds = append(seeds, key)
			continue
		}
		gap := "gap:seed:" + key
		value.addRawNode(gap, "gap")
		seeds = append(seeds, gap)
	}
	return seeds
}

func (value *Graph) addEventEdge(from, to, kind, eventID string, incomplete bool) {
	value.addEdge(from, to, kind)
	id := kind + ":" + from + "->" + to
	edge := value.edges[id]
	if eventID != "" && !containsString(edge.EventRefs, eventID) {
		edge.EventRefs = append(edge.EventRefs, eventID)
	}
	edge.Incomplete = edge.Incomplete || incomplete
	value.edges[id] = edge
}

func (value *Graph) addRawNode(id, kind string) {
	if id == "" {
		return
	}
	if _, exists := value.nodes[id]; exists {
		return
	}
	value.nodes[id] = domaintelemetry.GraphNode{ID: id, Kind: kind, Label: id}
	value.nodeOrder = append(value.nodeOrder, id)
}

func entityID(kind, key string) string {
	return entity.Normalize(domaintelemetry.Entity{Kind: kind, Key: key}).Key
}

func mergeSubgraph(subgraph domaintelemetry.EvidenceSubgraph, nodes, edges map[string]bool) {
	for _, node := range subgraph.Nodes {
		nodes[node.ID] = true
	}
	for _, edge := range subgraph.Edges {
		edges[edge.ID] = true
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
