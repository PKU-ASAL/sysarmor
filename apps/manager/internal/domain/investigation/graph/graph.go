package graph

import (
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Graph struct {
	nodes     map[string]domaintelemetry.GraphNode
	nodeOrder []string
	edges     map[string]domaintelemetry.GraphEdge
	edgeOrder []string
	adjacency map[string][]string
}

type pathParent struct {
	node string
	edge string
}

func New() *Graph {
	return &Graph{
		nodes:     make(map[string]domaintelemetry.GraphNode),
		edges:     make(map[string]domaintelemetry.GraphEdge),
		adjacency: make(map[string][]string),
	}
}

func (value *Graph) EvidenceSubgraph() domaintelemetry.EvidenceSubgraph {
	if value == nil {
		return domaintelemetry.EvidenceSubgraph{}
	}
	nodes := make([]domaintelemetry.GraphNode, 0, len(value.nodeOrder))
	for _, id := range value.nodeOrder {
		nodes = append(nodes, value.nodes[id])
	}
	edges := make([]domaintelemetry.GraphEdge, 0, len(value.edgeOrder))
	for _, id := range value.edgeOrder {
		edges = append(edges, value.edges[id])
	}
	return domaintelemetry.EvidenceSubgraph{Nodes: nodes, Edges: edges}
}

func (value *Graph) KHop(seed string, hops int) domaintelemetry.EvidenceSubgraph {
	if value == nil || seed == "" || hops < 0 || !value.hasNode(seed) {
		return domaintelemetry.EvidenceSubgraph{}
	}
	seenNodes := map[string]bool{seed: true}
	seenEdges := make(map[string]bool)
	frontier := []string{seed}
	for depth := 0; depth < hops && len(frontier) > 0; depth++ {
		frontier = value.expand(frontier, seenNodes, seenEdges)
	}
	return value.subgraph(seenNodes, seenEdges)
}

func (value *Graph) ShortestPath(from, to string) domaintelemetry.EvidenceSubgraph {
	if value == nil || from == "" || to == "" || !value.hasNode(from) || !value.hasNode(to) {
		return domaintelemetry.EvidenceSubgraph{}
	}
	if from == to {
		return value.subgraph(map[string]bool{from: true}, nil)
	}
	parents := make(map[string]pathParent)
	seen, queue := map[string]bool{from: true}, []string{from}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		found, next := value.discover(node, to, seen, parents)
		if found {
			return value.pathSubgraph(from, to, parents)
		}
		queue = append(queue, next...)
	}
	return domaintelemetry.EvidenceSubgraph{}
}

func (value *Graph) expand(frontier []string, nodes, edges map[string]bool) []string {
	var next []string
	for _, node := range frontier {
		for _, edgeID := range value.adjacency[node] {
			edge := value.edges[edgeID]
			other, connected := adjacent(edge, node)
			if !connected {
				continue
			}
			edges[edgeID] = true
			if !nodes[other] {
				nodes[other] = true
				next = append(next, other)
			}
		}
	}
	return next
}

func (value *Graph) discover(node, target string, seen map[string]bool, parents map[string]pathParent) (bool, []string) {
	var next []string
	for _, edgeID := range value.adjacency[node] {
		other, connected := adjacent(value.edges[edgeID], node)
		if !connected || seen[other] {
			continue
		}
		seen[other] = true
		parents[other] = pathParent{node: node, edge: edgeID}
		if other == target {
			return true, nil
		}
		next = append(next, other)
	}
	return false, next
}

func (value *Graph) addNode(current domaintelemetry.Entity) {
	if current.Key == "" {
		return
	}
	if _, exists := value.nodes[current.Key]; exists {
		return
	}
	value.nodes[current.Key] = domaintelemetry.GraphNode{
		ID: current.Key, Kind: current.Kind, Label: current.Key, Entities: []domaintelemetry.Entity{current},
	}
	value.nodeOrder = append(value.nodeOrder, current.Key)
}

func (value *Graph) addEdge(from, to, kind string) {
	if from == "" || to == "" || from == to {
		return
	}
	id := kind + ":" + from + "->" + to
	if _, exists := value.edges[id]; exists {
		return
	}
	value.edges[id] = domaintelemetry.GraphEdge{ID: id, From: from, To: to, Kind: kind}
	value.edgeOrder = append(value.edgeOrder, id)
	value.adjacency[from] = append(value.adjacency[from], id)
	value.adjacency[to] = append(value.adjacency[to], id)
}

func (value *Graph) pathSubgraph(from, to string, parents map[string]pathParent) domaintelemetry.EvidenceSubgraph {
	nodes, edges := map[string]bool{to: true}, make(map[string]bool)
	for current := to; current != from; {
		parent, ok := parents[current]
		if !ok {
			return domaintelemetry.EvidenceSubgraph{}
		}
		nodes[parent.node], edges[parent.edge], current = true, true, parent.node
	}
	return value.subgraph(nodes, edges)
}

func (value *Graph) subgraph(nodes, edges map[string]bool) domaintelemetry.EvidenceSubgraph {
	result := domaintelemetry.EvidenceSubgraph{}
	for _, id := range value.nodeOrder {
		if nodes[id] {
			result.Nodes = append(result.Nodes, value.nodes[id])
		}
	}
	for _, id := range value.edgeOrder {
		if edges[id] {
			result.Edges = append(result.Edges, value.edges[id])
		}
	}
	return result
}

func (value *Graph) hasNode(id string) bool {
	_, exists := value.nodes[id]
	return exists
}

func adjacent(edge domaintelemetry.GraphEdge, node string) (string, bool) {
	if edge.From == node {
		return edge.To, true
	}
	if edge.To == node {
		return edge.From, true
	}
	return "", false
}
