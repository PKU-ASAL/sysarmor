package runtime

import domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"

func domainRules(rules []effectiveRule) []domaindetection.Rule {
	out := make([]domaindetection.Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, domainRule(rule.spec))
	}
	return out
}

func domainRule(spec RuleSpec) domaindetection.Rule {
	return domaindetection.Rule{
		ID:          spec.RuleID,
		Runtime:     spec.Runtime,
		RuntimeType: spec.RuntimeType,
		Expression: domaindetection.Expression{
			Conditions:     domainConditions(spec.Expr.Conditions),
			ConditionGroup: domainConditionNode(spec.Expr.ConditionGroup),
		},
		Sequence: domaindetection.Sequence{
			Within: spec.Sequence.Within,
			By:     spec.Sequence.By,
			Steps:  domainSteps(spec.Sequence.Steps),
		},
		Correlate: domaindetection.Correlate{
			Within:     spec.Correlate.Within,
			WithinText: spec.Correlate.WithinText,
			By:         spec.Correlate.By,
			Facts:      domainFacts(spec.Correlate.Facts),
		},
		Suppression: domaindetection.Suppression{
			Within: spec.Suppression.Within,
			By:     spec.Suppression.By,
		},
	}
}

func domainSteps(steps []StepSpec) []domaindetection.Step {
	out := make([]domaindetection.Step, 0, len(steps))
	for _, step := range steps {
		out = append(out, domaindetection.Step{
			ID: step.ID, Behavior: step.Behavior,
			Conditions: domainConditions(step.Conditions), ConditionGroup: domainConditionNode(step.ConditionGroup),
		})
	}
	return out
}

func domainFacts(facts []FactSpec) []domaindetection.Fact {
	out := make([]domaindetection.Fact, 0, len(facts))
	for _, fact := range facts {
		out = append(out, domaindetection.Fact{
			ID: fact.ID, Event: fact.Event, Events: fact.Events,
			Conditions: domainConditions(fact.Conditions), ConditionGroup: domainConditionNode(fact.ConditionGroup),
		})
	}
	return out
}

func domainConditions(conditions []ConditionSpec) []domaindetection.Condition {
	out := make([]domaindetection.Condition, 0, len(conditions))
	for _, condition := range conditions {
		out = append(out, domaindetection.Condition{
			Field: condition.Field, Operator: condition.Op, Value: condition.Value, Values: condition.Values,
			Ref: condition.Ref, Step: condition.Step, StepField: condition.StepField,
		})
	}
	return out
}

func domainConditionNode(node *ConditionNodeSpec) *domaindetection.ConditionNode {
	if node == nil {
		return nil
	}
	out := &domaindetection.ConditionNode{
		All: domainConditionNodes(node.All), Any: domainConditionNodes(node.Any), Not: domainConditionNode(node.Not),
	}
	if node.Condition != nil {
		condition := domainConditions([]ConditionSpec{*node.Condition})[0]
		out.Condition = &condition
	}
	return out
}

func domainConditionNodes(nodes []ConditionNodeSpec) []domaindetection.ConditionNode {
	if nodes == nil {
		return nil
	}
	out := make([]domaindetection.ConditionNode, 0, len(nodes))
	for i := range nodes {
		out = append(out, *domainConditionNode(&nodes[i]))
	}
	return out
}
