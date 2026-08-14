package runtime

import (
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

func (r *Runtime) contentStore() *agentcontent.Store {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.content == nil {
		r.content = agentcontent.NewStore()
	}
	return r.content
}

func (r *Runtime) detectionContentSnapshot() detection.ContentSnapshot {
	return detectionContentSnapshotFromContent(r.contentStore().Snapshot())
}

func detectionContentSnapshotFromContent(snapshot agentcontent.Snapshot) detection.ContentSnapshot {
	out := detection.ContentSnapshot{
		ContextRefs: make(map[string]detection.ContentRef),
		IOCRefs:     make(map[string]detection.ContentRef),
	}
	for ref, set := range snapshot.ContextSets {
		out.ContextRefs[ref] = detection.ContentRef{
			Ref:     set.Ref,
			Version: set.Version,
			Digest:  set.Digest,
			Values:  append([]string(nil), set.Values...),
		}
	}
	for ref, set := range snapshot.IOCPacks {
		out.IOCRefs[ref] = detection.ContentRef{
			Ref:     set.Ref,
			Version: set.Version,
			Digest:  set.Digest,
			Values:  append([]string(nil), set.Values...),
		}
	}
	for _, rule := range snapshot.Rules {
		out.Rules = append(out.Rules, detection.RuleSpec{
			RuleID:            rule.RuleID,
			Version:           rule.Version,
			RuleSetRef:        rule.RuleSetRef,
			Severity:          rule.Severity,
			Runtime:           rule.RuntimeEntry,
			RuntimeType:       rule.RuntimeType,
			Expr:              detectionExpr(rule.Expr),
			Sequence:          detectionSequence(rule.Sequence),
			Correlate:         detectionCorrelate(rule.Correlate),
			Suppression:       detectionSuppression(rule.Suppression),
			RequiredEvents:    detectionRequiredEvents(rule.RequiredEvents),
			RequiredBehaviors: requiredBehaviors(rule.RequiredEvents),
			ContextRefs:       append([]string(nil), rule.ContextRefs...),
			IOCRefs:           append([]string(nil), rule.IOCRefs...),
			ResponseIntent: &detection.ResponseIntent{
				Action:     rule.ResponseIntent.Action,
				Confidence: rule.ResponseIntent.Confidence,
				Reason:     rule.ResponseIntent.Reason,
			},
			Terminal: rule.Terminal,
		})
	}
	return out
}

func detectionContentRefs(snapshot agentcontent.Snapshot) []agenthealth.ContentRef {
	var out []agenthealth.ContentRef
	for ref, record := range snapshot.RulePacks {
		out = append(out, agenthealth.ContentRef{Ref: ref, Kind: record.Kind, Version: record.Version, Digest: record.Digest})
	}
	for ref, set := range snapshot.ContextSets {
		out = append(out, agenthealth.ContentRef{Ref: ref, Kind: "contextset", Version: set.Version, Digest: set.Digest})
	}
	for ref, set := range snapshot.IOCPacks {
		out = append(out, agenthealth.ContentRef{Ref: ref, Kind: "iocpack", Version: set.Version, Digest: set.Digest})
	}
	return out
}

func detectionRequiredEvents(events []agentcontent.RequiredEvent) []detection.RequiredEventSpec {
	out := make([]detection.RequiredEventSpec, 0, len(events))
	for _, event := range events {
		out = append(out, detection.RequiredEventSpec{
			Behavior: event.Behavior,
			Fields:   append([]string(nil), event.Fields...),
		})
	}
	return out
}

func detectionExpr(expr agentcontent.RuntimeExpr) detection.ExprSpec {
	out := detection.ExprSpec{
		Conditions:     make([]detection.ConditionSpec, 0, len(expr.Conditions)),
		ConditionGroup: detectionConditionNode(expr.ConditionGroup),
	}
	for _, cond := range expr.Conditions {
		out.Conditions = append(out.Conditions, detectionCondition(cond))
	}
	return out
}

func detectionSequence(seq agentcontent.RuntimeSequence) detection.SequenceSpec {
	within, _ := time.ParseDuration(seq.Within)
	out := detection.SequenceSpec{
		Within: within,
		By:     append([]string(nil), seq.By...),
		Steps:  make([]detection.StepSpec, 0, len(seq.Steps)),
	}
	for _, step := range seq.Steps {
		behavior := step.Behavior
		if behavior == "" {
			behavior = step.Event
		}
		next := detection.StepSpec{
			ID:             step.ID,
			Behavior:       domainevent.NormalizeBehavior(behavior),
			Conditions:     make([]detection.ConditionSpec, 0, len(step.Conditions)),
			ConditionGroup: detectionConditionNode(step.ConditionGroup),
		}
		for _, cond := range step.Conditions {
			next.Conditions = append(next.Conditions, detectionCondition(cond))
		}
		out.Steps = append(out.Steps, next)
	}
	return out
}

func detectionCorrelate(spec agentcontent.RuntimeCorrelate) detection.CorrelateSpec {
	within, _ := time.ParseDuration(spec.Within)
	out := detection.CorrelateSpec{
		Within:     within,
		WithinText: spec.Within,
		By:         append([]string(nil), spec.By...),
		Facts:      make([]detection.FactSpec, 0, len(spec.Facts)),
	}
	for _, fact := range spec.Facts {
		next := detection.FactSpec{
			ID:             fact.ID,
			Event:          fact.Event,
			Events:         append([]string(nil), fact.Events...),
			Conditions:     make([]detection.ConditionSpec, 0, len(fact.Conditions)),
			ConditionGroup: detectionConditionNode(fact.ConditionGroup),
		}
		for _, condition := range fact.Conditions {
			next.Conditions = append(next.Conditions, detectionCondition(condition))
		}
		out.Facts = append(out.Facts, next)
	}
	return out
}

func detectionConditionNode(node *agentcontent.RuntimeConditionNode) *detection.ConditionNodeSpec {
	if node == nil {
		return nil
	}
	out := &detection.ConditionNodeSpec{}
	if node.All != nil {
		out.All = make([]detection.ConditionNodeSpec, 0, len(node.All))
		for i := range node.All {
			out.All = append(out.All, *detectionConditionNode(&node.All[i]))
		}
	}
	if node.Any != nil {
		out.Any = make([]detection.ConditionNodeSpec, 0, len(node.Any))
		for i := range node.Any {
			out.Any = append(out.Any, *detectionConditionNode(&node.Any[i]))
		}
	}
	out.Not = detectionConditionNode(node.Not)
	if node.Condition != nil {
		condition := detectionCondition(*node.Condition)
		out.Condition = &condition
	}
	return out
}

func detectionSuppression(spec agentcontent.RuntimeSuppression) detection.SuppressionSpec {
	within, _ := time.ParseDuration(spec.Within)
	return detection.SuppressionSpec{Within: within, By: append([]string(nil), spec.By...)}
}

func detectionCondition(cond agentcontent.RuntimeCondition) detection.ConditionSpec {
	return detection.ConditionSpec{
		Field:     cond.Field,
		Op:        cond.Op,
		Value:     cond.Value,
		Values:    append([]string(nil), cond.Values...),
		Ref:       cond.Ref,
		Step:      cond.Step,
		StepField: cond.StepField,
	}
}

func requiredBehaviors(events []agentcontent.RequiredEvent) []string {
	seen := map[string]bool{}
	var out []string
	for _, event := range events {
		behavior := domainevent.NormalizeBehavior(event.Behavior)
		if behavior == "" || seen[behavior] {
			continue
		}
		seen[behavior] = true
		out = append(out, behavior)
	}
	return out
}
