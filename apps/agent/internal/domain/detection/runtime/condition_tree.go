package runtime

type compiledConditionNodeKind uint8

const (
	conditionNodeAll compiledConditionNodeKind = iota + 1
	conditionNodeAny
	conditionNodeNot
	conditionNodeLeaf
)

type compiledConditionNode struct {
	kind      compiledConditionNodeKind
	children  []compiledConditionNode
	child     *compiledConditionNode
	condition compiledCondition
}

func compileConditionNode(node *ConditionNodeSpec, content ContentSnapshot) *compiledConditionNode {
	if node == nil {
		return nil
	}
	out := &compiledConditionNode{}
	switch {
	case node.Condition != nil:
		out.kind = conditionNodeLeaf
		out.condition = compileCondition(*node.Condition, content)
	case node.Not != nil:
		out.kind = conditionNodeNot
		out.child = compileConditionNode(node.Not, content)
	case node.All != nil:
		out.kind = conditionNodeAll
		out.children = compileConditionNodes(node.All, content)
	case node.Any != nil:
		out.kind = conditionNodeAny
		out.children = compileConditionNodes(node.Any, content)
	}
	return out
}

func compileConditionNodes(nodes []ConditionNodeSpec, content ContentSnapshot) []compiledConditionNode {
	out := make([]compiledConditionNode, 0, len(nodes))
	for i := range nodes {
		out = append(out, *compileConditionNode(&nodes[i], content))
	}
	return out
}

func appendCompiledNodeConditions(out []compiledCondition, node *compiledConditionNode) []compiledCondition {
	if node == nil {
		return out
	}
	if node.kind == conditionNodeLeaf {
		return append(out, node.condition)
	}
	if node.child != nil {
		out = appendCompiledNodeConditions(out, node.child)
	}
	for i := range node.children {
		out = appendCompiledNodeConditions(out, &node.children[i])
	}
	return out
}

func (e *Engine) matchCompiledConditionNode(view eventView, node *compiledConditionNode, st *cepGroupState) bool {
	if node == nil {
		return true
	}
	switch node.kind {
	case conditionNodeLeaf:
		return e.matchCompiledCondition(view, node.condition, st)
	case conditionNodeNot:
		return node.child != nil && !e.matchCompiledConditionNode(view, node.child, st)
	case conditionNodeAll:
		return e.matchAllConditionNodes(view, node.children, st)
	case conditionNodeAny:
		return e.matchAnyConditionNode(view, node.children, st)
	default:
		return false
	}
}

func (e *Engine) matchAllConditionNodes(view eventView, nodes []compiledConditionNode, st *cepGroupState) bool {
	for i := range nodes {
		if !e.matchCompiledConditionNode(view, &nodes[i], st) {
			return false
		}
	}
	return true
}

func (e *Engine) matchAnyConditionNode(view eventView, nodes []compiledConditionNode, st *cepGroupState) bool {
	for i := range nodes {
		if e.matchCompiledConditionNode(view, &nodes[i], st) {
			return true
		}
	}
	return false
}
