package detection

import (
	"strings"
	"time"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/packages/eventmodel"
)

type compiledCorrelateRuntime struct {
	byBehavior map[string][]compiledCorrelateRule
}

type compiledCorrelateRule struct {
	rule   effectiveRule
	within time.Duration
	by     []fieldID
	facts  []compiledFact
}

type compiledFact struct {
	id             string
	behaviors      map[string]bool
	conditions     []compiledCondition
	conditionGroup *compiledConditionNode
}

type correlateRuleState struct {
	Groups map[string]*correlateGroupState
}

type correlateGroupState struct {
	ExpiresAt uint64
	Facts     map[string]correlateFactMatch
}

type correlateFactMatch struct {
	EventID  string
	Entities []domaindetection.Entity
}

func compileCorrelateRuntime(rules []effectiveRule, content ContentSnapshot) compiledCorrelateRuntime {
	runtime := compiledCorrelateRuntime{byBehavior: make(map[string][]compiledCorrelateRule)}
	for _, rule := range rules {
		if !rule.enabled || rule.runtimeType() != "correlate" {
			continue
		}
		compiled := compileCorrelateRule(rule, content)
		behaviors := make(map[string]bool)
		for _, fact := range compiled.facts {
			for behavior := range fact.behaviors {
				behaviors[behavior] = true
			}
		}
		for behavior := range behaviors {
			runtime.byBehavior[behavior] = append(runtime.byBehavior[behavior], compiled)
		}
	}
	return runtime
}

func compileCorrelateRule(rule effectiveRule, content ContentSnapshot) compiledCorrelateRule {
	out := compiledCorrelateRule{
		rule: rule, within: rule.spec.Correlate.Within, by: compileFields(rule.spec.Correlate.By),
		facts: make([]compiledFact, 0, len(rule.spec.Correlate.Facts)),
	}
	for _, fact := range rule.spec.Correlate.Facts {
		out.facts = append(out.facts, compiledFact{
			id:             strings.TrimSpace(fact.ID),
			behaviors:      compileFactBehaviors(fact),
			conditions:     compileConditions(fact.Conditions, content),
			conditionGroup: compileConditionNode(fact.ConditionGroup, content),
		})
	}
	return out
}

func compileFactBehaviors(fact FactSpec) map[string]bool {
	out := make(map[string]bool)
	behaviors := append([]string(nil), fact.Events...)
	if strings.TrimSpace(fact.Event) != "" {
		behaviors = append(behaviors, fact.Event)
	}
	for _, behavior := range behaviors {
		normalized := eventmodel.NormalizeBehavior(behavior).String()
		if normalized != "" {
			out[normalized] = true
		}
	}
	return out
}

func (runtime compiledCorrelateRuntime) rulesForBehavior(behavior string) []compiledCorrelateRule {
	return runtime.byBehavior[behavior]
}

func (e *Engine) detectCorrelateRule(view eventView, rule compiledCorrelateRule) *domaindetection.Signal {
	state := e.correlate[rule.rule.spec.RuleID]
	if state == nil {
		state = &correlateRuleState{Groups: make(map[string]*correlateGroupState)}
		e.correlate[rule.rule.spec.RuleID] = state
	}
	groupKey := e.compiledSequenceGroupKey(view, rule.by)
	now := view.eventTime()
	group := state.Groups[groupKey]
	if group != nil && group.ExpiresAt > 0 && now > group.ExpiresAt {
		delete(state.Groups, groupKey)
		e.metrics.ExpiredCEPGroups++
		group = nil
	}
	matched := e.matchCorrelateFacts(view, rule.facts)
	if len(matched) == 0 {
		return nil
	}
	if group == nil {
		e.evictCorrelateGroups(state, now)
		group = &correlateGroupState{
			ExpiresAt: now + uint64(rule.within.Nanoseconds()),
			Facts:     make(map[string]correlateFactMatch),
		}
		state.Groups[groupKey] = group
	}
	for _, fact := range matched {
		group.Facts[fact.id] = correlateFactMatch{EventID: view.eventID, Entities: eventEntities(view.ev)}
	}
	if len(group.Facts) < len(rule.facts) {
		return nil
	}
	refs, entities := e.correlateEvidence(group, rule.facts)
	delete(state.Groups, groupKey)
	return e.signal(view.ev, rule.rule, refs, rule.rule.terminal(false), entities...)
}

func (e *Engine) matchCorrelateFacts(view eventView, facts []compiledFact) []compiledFact {
	var out []compiledFact
	for _, fact := range facts {
		if !fact.behaviors[view.behavior] {
			continue
		}
		if e.matchCompiledConditions(view, fact.conditions, nil) && e.matchCompiledConditionNode(view, fact.conditionGroup, nil) {
			out = append(out, fact)
		}
	}
	return out
}

func (e *Engine) correlateEvidence(group *correlateGroupState, facts []compiledFact) ([]string, []domaindetection.Entity) {
	var refs []string
	var entities []domaindetection.Entity
	for _, fact := range facts {
		match := group.Facts[fact.id]
		refs = appendUnique(refs, match.EventID)
		entities = appendUniqueEntities(entities, match.Entities...)
	}
	if len(refs) > e.limits.MaxCEPRefs {
		e.metrics.DroppedEventRefs += uint64(len(refs) - e.limits.MaxCEPRefs)
		refs = refs[len(refs)-e.limits.MaxCEPRefs:]
	}
	return refs, entities
}

func appendUniqueEntities(out []domaindetection.Entity, values ...domaindetection.Entity) []domaindetection.Entity {
	for _, value := range values {
		found := false
		for _, current := range out {
			if current == value {
				found = true
				break
			}
		}
		if !found {
			out = append(out, value)
		}
	}
	return out
}

func (e *Engine) evictCorrelateGroups(state *correlateRuleState, now uint64) {
	if state == nil || len(state.Groups) < e.limits.MaxCEPGroups {
		return
	}
	for key, group := range state.Groups {
		if group.ExpiresAt > 0 && now > group.ExpiresAt {
			delete(state.Groups, key)
			e.metrics.ExpiredCEPGroups++
		}
	}
	for len(state.Groups) >= e.limits.MaxCEPGroups {
		for key := range state.Groups {
			delete(state.Groups, key)
			e.metrics.EvictedCEPGroups++
			break
		}
	}
}
