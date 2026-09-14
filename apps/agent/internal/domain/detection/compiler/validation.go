package compiler

import (
	"fmt"
	"strings"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
)

const maxWindow = 24 * time.Hour
const maxConditionTreeDepth = 8
const maxConditionTreeLeaves = 256

func Validate(rules []detection.Rule) []string {
	var errors []string
	for _, rule := range rules {
		errors = append(errors, validateRule(rule)...)
	}
	return errors
}

func validateRule(rule detection.Rule) []string {
	runtime := runtimeType(rule)
	errors := validateRuleShape(rule, runtime)
	errors = append(errors, validateSuppression(rule)...)
	switch runtime {
	case "expr":
		errors = append(errors, validateConditions(rule.ID, "expr", rule.Expression.Conditions, nil)...)
		return append(errors, validateConditionTree(rule.ID, "expr", rule.Expression.ConditionGroup, nil)...)
	case "sequence":
		return append(errors, validateSequence(rule)...)
	case "correlate":
		return append(errors, validateCorrelate(rule)...)
	default:
		return errors
	}
}

func validateRuleShape(rule detection.Rule, runtime string) []string {
	var errors []string
	switch runtime {
	case "", "expr", "sequence", "correlate":
	default:
		errors = append(errors, fmt.Sprintf("rule %s has unsupported runtime type %q", rule.ID, runtime))
	}
	if runtime == "expr" && len(rule.Expression.Conditions) == 0 && rule.Expression.ConditionGroup == nil {
		errors = append(errors, fmt.Sprintf("rule %s expr runtime requires conditions", rule.ID))
	}
	if runtime == "sequence" {
		if len(rule.Sequence.Steps) == 0 {
			errors = append(errors, fmt.Sprintf("rule %s sequence runtime requires steps", rule.ID))
		}
		for _, step := range rule.Sequence.Steps {
			if strings.TrimSpace(step.ID) == "" {
				errors = append(errors, fmt.Sprintf("rule %s sequence step id is required", rule.ID))
			}
			if strings.TrimSpace(step.Behavior) == "" {
				errors = append(errors, fmt.Sprintf("rule %s sequence step %s behavior is required", rule.ID, step.ID))
			}
		}
	}
	if runtime == "correlate" && len(rule.Correlate.Facts) == 0 {
		errors = append(errors, fmt.Sprintf("rule %s correlate runtime requires facts", rule.ID))
	}
	return errors
}

func validateCorrelate(rule detection.Rule) []string {
	spec := rule.Correlate
	var errors []string
	if spec.WithinText != "" {
		if _, err := time.ParseDuration(spec.WithinText); err != nil {
			errors = append(errors, fmt.Sprintf("rule %s has invalid correlate window %q", rule.ID, spec.WithinText))
		}
	}
	if spec.Within <= 0 || spec.Within > maxWindow {
		errors = append(errors, fmt.Sprintf("rule %s correlate window must be within (0, %s]", rule.ID, maxWindow))
	}
	if len(spec.By) == 0 {
		errors = append(errors, fmt.Sprintf("rule %s correlate by field is required", rule.ID))
	}
	for _, field := range spec.By {
		if ParseField(field) == FieldUnknown {
			errors = append(errors, fmt.Sprintf("rule %s has unsupported correlate by field %q", rule.ID, field))
		}
	}
	if len(spec.Facts) < 2 {
		errors = append(errors, fmt.Sprintf("rule %s correlate requires at least two facts", rule.ID))
	}
	return append(errors, validateFacts(rule.ID, spec.Facts)...)
}

func validateFacts(ruleID string, facts []detection.Fact) []string {
	seen := make(map[string]bool, len(facts))
	var errors []string
	for _, fact := range facts {
		id := strings.TrimSpace(fact.ID)
		if id == "" {
			errors = append(errors, fmt.Sprintf("rule %s correlate fact id is required", ruleID))
		} else if seen[id] {
			errors = append(errors, fmt.Sprintf("rule %s correlate has duplicate fact %q", ruleID, id))
		}
		seen[id] = true
		hasEvent, hasEvents := strings.TrimSpace(fact.Event) != "", len(fact.Events) > 0
		if hasEvent == hasEvents {
			errors = append(errors, fmt.Sprintf("rule %s correlate fact %s must set exactly one of event or events", ruleID, id))
		}
		for _, behavior := range fact.Events {
			if strings.TrimSpace(behavior) == "" {
				errors = append(errors, fmt.Sprintf("rule %s correlate fact %s behavior is required", ruleID, id))
			}
		}
		errors = append(errors, validateConditions(ruleID, "fact "+id, fact.Conditions, nil)...)
		errors = append(errors, validateConditionTree(ruleID, "fact "+id, fact.ConditionGroup, nil)...)
	}
	return errors
}

func validateSuppression(rule detection.Rule) []string {
	spec := rule.Suppression
	if spec.Within == 0 && len(spec.By) == 0 {
		return nil
	}
	var errors []string
	if runtimeType(rule) != "expr" {
		errors = append(errors, fmt.Sprintf("rule %s suppression requires expr runtime", rule.ID))
	}
	if spec.Within <= 0 || spec.Within > maxWindow {
		errors = append(errors, fmt.Sprintf("rule %s suppression window must be between 0 and %s", rule.ID, maxWindow))
	}
	if len(spec.By) == 0 {
		errors = append(errors, fmt.Sprintf("rule %s suppression by field is required", rule.ID))
	}
	for _, field := range spec.By {
		if ParseField(field) == FieldUnknown {
			errors = append(errors, fmt.Sprintf("rule %s has unsupported suppression by field %q", rule.ID, field))
		}
	}
	return errors
}

func validateSequence(rule detection.Rule) []string {
	var errors []string
	for _, field := range rule.Sequence.By {
		if ParseField(field) == FieldUnknown {
			errors = append(errors, fmt.Sprintf("rule %s sequence has unsupported by field %q", rule.ID, field))
		}
	}
	prior := make(map[string]bool, len(rule.Sequence.Steps))
	for _, step := range rule.Sequence.Steps {
		id := strings.TrimSpace(step.ID)
		if prior[id] {
			errors = append(errors, fmt.Sprintf("rule %s sequence has duplicate step %q", rule.ID, id))
		}
		errors = append(errors, validateConditions(rule.ID, "step "+id, step.Conditions, prior)...)
		errors = append(errors, validateConditionTree(rule.ID, "step "+id, step.ConditionGroup, prior)...)
		prior[id] = true
	}
	return errors
}

func validateConditionTree(ruleID, location string, node *detection.ConditionNode, prior map[string]bool) []string {
	if node == nil {
		return nil
	}
	leaves := 0
	return validateConditionNode(ruleID, location, node, prior, 1, &leaves)
}

func validateConditionNode(ruleID, location string, node *detection.ConditionNode, prior map[string]bool, depth int, leaves *int) []string {
	if depth > maxConditionTreeDepth {
		return []string{fmt.Sprintf("rule %s %s condition tree exceeds maximum depth %d", ruleID, location, maxConditionTreeDepth)}
	}
	if boolCount(node.Condition != nil, node.Not != nil, node.All != nil, node.Any != nil) != 1 {
		return []string{fmt.Sprintf("rule %s %s condition node must set exactly one kind", ruleID, location)}
	}
	if node.Condition != nil {
		*leaves++
		if *leaves > maxConditionTreeLeaves {
			return []string{fmt.Sprintf("rule %s %s condition tree exceeds maximum leaves %d", ruleID, location, maxConditionTreeLeaves)}
		}
		return validateConditions(ruleID, location, []detection.Condition{*node.Condition}, prior)
	}
	if node.Not != nil {
		return validateConditionNode(ruleID, location, node.Not, prior, depth+1, leaves)
	}
	children, group := node.All, "all"
	if node.Any != nil {
		children, group = node.Any, "any"
	}
	if len(children) == 0 {
		return []string{fmt.Sprintf("rule %s %s %s requires children", ruleID, location, group)}
	}
	var errors []string
	for i := range children {
		errors = append(errors, validateConditionNode(ruleID, location, &children[i], prior, depth+1, leaves)...)
	}
	return errors
}

func validateConditions(ruleID, location string, conditions []detection.Condition, prior map[string]bool) []string {
	var errors []string
	for _, condition := range conditions {
		if ParseField(condition.Field) == FieldUnknown {
			errors = append(errors, fmt.Sprintf("rule %s %s has unsupported field %q", ruleID, location, condition.Field))
		}
		operator := ParseOperator(condition.Operator)
		if operator == OperatorUnknown {
			errors = append(errors, fmt.Sprintf("rule %s %s has unsupported operator %q", ruleID, location, condition.Operator))
			continue
		}
		if operator != OperatorSameAs {
			continue
		}
		step := strings.TrimSpace(condition.Step)
		if prior == nil || step == "" || !prior[step] {
			errors = append(errors, fmt.Sprintf("rule %s %s same_as references unknown prior step %q", ruleID, location, step))
		}
		if ParseField(firstNonEmpty(condition.StepField, condition.Field)) == FieldUnknown {
			errors = append(errors, fmt.Sprintf("rule %s %s has unsupported step field %q", ruleID, location, condition.StepField))
		}
	}
	return errors
}

func runtimeType(rule detection.Rule) string {
	if rule.RuntimeType != "" {
		return strings.ToLower(strings.TrimSpace(rule.RuntimeType))
	}
	runtime := strings.ToLower(strings.TrimSpace(rule.Runtime))
	switch runtime {
	case "expr", "sequence", "correlate":
		return runtime
	default:
		return ""
	}
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
