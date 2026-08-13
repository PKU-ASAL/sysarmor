package runtime

import (
	"path/filepath"
	"strings"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
)

func sequenceEvidenceEntities(view eventView, step compiledStep, state *cepGroupState) []domaindetection.Entity {
	conditions := matchedPositiveConditions(view, step.conditions, state)
	groupConditions, _ := matchedPositiveNodeConditions(view, step.conditionGroup, state)
	conditions = append(conditions, groupConditions...)
	var entities []domaindetection.Entity
	for _, condition := range conditions {
		if !positiveArgvCondition(condition) {
			continue
		}
		entities = append(entities, matchingArgumentEntities(view, condition)...)
	}
	return entities
}

func matchedPositiveConditions(view eventView, conditions []compiledCondition, state *cepGroupState) []compiledCondition {
	var result []compiledCondition
	for _, condition := range conditions {
		if compiledConditionMatches(view, condition, state) {
			result = append(result, condition)
		}
	}
	return result
}

func matchedPositiveNodeConditions(view eventView, node *compiledConditionNode, state *cepGroupState) ([]compiledCondition, bool) {
	if node == nil {
		return nil, true
	}
	switch node.kind {
	case conditionNodeLeaf:
		matched := compiledConditionMatches(view, node.condition, state)
		if matched {
			return []compiledCondition{node.condition}, true
		}
		return nil, false
	case conditionNodeNot:
		_, matched := matchedPositiveNodeConditions(view, node.child, state)
		return nil, node.child != nil && !matched
	case conditionNodeAll:
		return matchedAllNodeConditions(view, node.children, state)
	case conditionNodeAny:
		return matchedAnyNodeConditions(view, node.children, state)
	default:
		return nil, false
	}
}

func matchedAllNodeConditions(view eventView, nodes []compiledConditionNode, state *cepGroupState) ([]compiledCondition, bool) {
	var result []compiledCondition
	for index := range nodes {
		conditions, matched := matchedPositiveNodeConditions(view, &nodes[index], state)
		if !matched {
			return nil, false
		}
		result = append(result, conditions...)
	}
	return result, true
}

func matchedAnyNodeConditions(view eventView, nodes []compiledConditionNode, state *cepGroupState) ([]compiledCondition, bool) {
	for index := range nodes {
		if conditions, matched := matchedPositiveNodeConditions(view, &nodes[index], state); matched {
			return conditions, true
		}
	}
	return nil, false
}

func positiveArgvCondition(condition compiledCondition) bool {
	if condition.field != fieldProcessArgv || condition.matcher == nil {
		return false
	}
	switch condition.op {
	case opEq, opIn, opContains, opPrefix, opSuffix:
		return true
	default:
		return false
	}
}

func matchingArgumentEntities(view eventView, condition compiledCondition) []domaindetection.Entity {
	var entities []domaindetection.Entity
	for _, argument := range view.ev.Subject.Argv {
		argument = strings.Trim(argument, "'\"")
		if filepath.IsAbs(argument) && condition.matcher.Match(argument) {
			entities = append(entities, fileEntity(argument, "subject"))
		}
	}
	return entities
}
