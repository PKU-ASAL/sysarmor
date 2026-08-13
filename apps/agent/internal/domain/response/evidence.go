package response

type EvidenceNode struct {
	ID    string
	Kind  string
	Label string
}

type EvidenceSubgraph struct {
	Nodes []EvidenceNode
}
