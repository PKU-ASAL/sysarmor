package content

import (
	"time"

	domaincontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/content"
)

func DomainSnapshot(value Snapshot) domaincontent.Snapshot {
	out := domaincontent.Snapshot{RulePacks: map[string]domaincontent.Record{}, ContextSets: map[string]domaincontent.ValueSet{}, IOCPacks: map[string]domaincontent.ValueSet{}, DefaultManifestVersion: value.DefaultManifestVersion}
	for key, record := range value.RulePacks {
		out.RulePacks[key] = domainRecord(record)
	}
	for key, set := range value.ContextSets {
		out.ContextSets[key] = domainValueSet(set)
	}
	for key, set := range value.IOCPacks {
		out.IOCPacks[key] = domainValueSet(set)
	}
	for _, rule := range value.Rules {
		out.Rules = append(out.Rules, domainRule(rule))
	}
	return out
}

func domainRecord(v Record) domaincontent.Record {
	return domaincontent.Record{Ref: v.Ref, Kind: v.Kind, Version: v.Version, Digest: v.Digest, Status: v.Status}
}
func domainValueSet(v ValueSet) domaincontent.ValueSet {
	return domaincontent.ValueSet{Ref: v.Ref, Version: v.Version, Digest: v.Digest, ValueType: v.ValueType, Values: append([]string(nil), v.Values...)}
}
func duration(value string) time.Duration { parsed, _ := time.ParseDuration(value); return parsed }
func domainRule(v Rule) domaincontent.Rule {
	out := domaincontent.Rule{RuleID: v.RuleID, Version: v.Version, RuleSetRef: v.RuleSetRef, Severity: v.Severity, RuntimeType: v.RuntimeType, RuntimeEntry: v.RuntimeEntry, ContextRefs: append([]string(nil), v.ContextRefs...), IOCRefs: append([]string(nil), v.IOCRefs...), Terminal: v.Terminal, ResponseIntent: domaincontent.ResponseIntent{Action: v.ResponseIntent.Action, Confidence: v.ResponseIntent.Confidence, Reason: v.ResponseIntent.Reason}}
	out.Expr = domaincontent.RuntimeExpr{Conditions: domainConditions(v.Expr.Conditions), ConditionGroup: domainNode(v.Expr.ConditionGroup)}
	out.Sequence = domaincontent.RuntimeSequence{Within: duration(v.Sequence.Within), By: append([]string(nil), v.Sequence.By...)}
	for _, step := range v.Sequence.Steps {
		out.Sequence.Steps = append(out.Sequence.Steps, domaincontent.RuntimeStep{ID: step.ID, Behavior: step.Behavior, Event: step.Event, Conditions: domainConditions(step.Conditions), ConditionGroup: domainNode(step.ConditionGroup)})
	}
	out.Correlate = domaincontent.RuntimeCorrelate{Within: duration(v.Correlate.Within), By: append([]string(nil), v.Correlate.By...)}
	for _, fact := range v.Correlate.Facts {
		out.Correlate.Facts = append(out.Correlate.Facts, domaincontent.RuntimeFact{ID: fact.ID, Event: fact.Event, Events: append([]string(nil), fact.Events...), Conditions: domainConditions(fact.Conditions), ConditionGroup: domainNode(fact.ConditionGroup)})
	}
	out.Suppression = domaincontent.RuntimeSuppression{Within: duration(v.Suppression.Within), By: append([]string(nil), v.Suppression.By...)}
	for _, event := range v.RequiredEvents {
		out.RequiredEvents = append(out.RequiredEvents, domaincontent.RequiredEvent{Behavior: event.Behavior, Fields: append([]string(nil), event.Fields...)})
	}
	return out
}

func (s *Store) DomainSnapshot() domaincontent.Snapshot { return DomainSnapshot(s.Snapshot()) }
func domainConditions(values []RuntimeCondition) []domaincontent.RuntimeCondition {
	out := make([]domaincontent.RuntimeCondition, 0, len(values))
	for _, v := range values {
		out = append(out, domaincontent.RuntimeCondition{Field: v.Field, Op: v.Op, Value: v.Value, Values: append([]string(nil), v.Values...), Ref: v.Ref, Step: v.Step, StepField: v.StepField})
	}
	return out
}
func domainNode(v *RuntimeConditionNode) *domaincontent.RuntimeConditionNode {
	if v == nil {
		return nil
	}
	out := &domaincontent.RuntimeConditionNode{Not: domainNode(v.Not)}
	for _, n := range v.All {
		out.All = append(out.All, *domainNode(&n))
	}
	for _, n := range v.Any {
		out.Any = append(out.Any, *domainNode(&n))
	}
	if v.Condition != nil {
		c := domainConditions([]RuntimeCondition{*v.Condition})[0]
		out.Condition = &c
	}
	return out
}
