package runtime

import (
	"path/filepath"
	"strconv"
	"strings"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func (e *Engine) detectCEPRules(view eventView) []*domaindetection.Signal {
	var out []*domaindetection.Signal
	for _, rule := range e.compiled.rulesForBehavior(view.behavior) {
		e.metrics.CEPRulesScanned++
		if !rule.rule.enabled {
			continue
		}
		e.metrics.CEPRulesEvaluated++
		switch rule.kind {
		case compiledRuleExpr:
			if e.matchCompiledConditions(view, rule.expr.conditions, nil) && e.matchCompiledConditionNode(view, rule.expr.conditionGroup, nil) {
				if e.suppressCompiledRule(view, rule) {
					continue
				}
				out = append(out, e.signal(view.ev, rule.rule, []string{view.eventID}, rule.rule.spec.Stage, eventEntities(view.ev)...))
			}
		}
	}
	for _, candidate := range e.sequence.candidatesForBehavior(view.behavior, e.cepActive) {
		e.metrics.CEPRulesScanned++
		if !candidate.rule.rule.enabled {
			continue
		}
		e.metrics.CEPRulesEvaluated++
		if sig := e.detectSequenceCandidate(view, candidate); sig != nil {
			out = append(out, sig)
		}
	}
	for _, rule := range e.correlation.rulesForBehavior(view.behavior) {
		e.metrics.CEPRulesScanned++
		e.metrics.CEPRulesEvaluated++
		if sig := e.detectCorrelateRule(view, rule); sig != nil {
			out = append(out, sig)
		}
	}
	return out
}

func (e *Engine) suppressCompiledRule(view eventView, rule compiledRule) bool {
	suppression := rule.expr.suppression
	if suppression.within <= 0 || len(suppression.by) == 0 {
		return false
	}
	parts := make([]string, 0, len(suppression.by)+1)
	parts = append(parts, "rule="+rule.rule.spec.RuleID)
	for _, field := range suppression.by {
		e.metrics.FieldReads++
		parts = append(parts, fieldName(field)+"="+view.field(field))
	}
	return e.suppressSignal(strings.Join(parts, "|"), eventWallTime(view.ev), suppression.within)
}

func (r effectiveRule) isCEP() bool {
	switch r.runtimeType() {
	case "expr", "sequence", "correlate":
		return true
	default:
		return false
	}
}

func (r effectiveRule) runtimeType() string {
	if r.spec.RuntimeType != "" {
		return strings.ToLower(strings.TrimSpace(r.spec.RuntimeType))
	}
	switch strings.ToLower(strings.TrimSpace(r.spec.Runtime)) {
	case "expr", "sequence", "correlate":
		return strings.ToLower(strings.TrimSpace(r.spec.Runtime))
	default:
		return ""
	}
}

func (e *Engine) detectSequenceRule(view eventView, rule compiledRule) *domaindetection.Signal {
	return e.detectSequenceCandidate(view, compiledSequenceCandidate{rule: rule, firstStep: true})
}

func (e *Engine) detectSequenceCandidate(view eventView, candidate compiledSequenceCandidate) *domaindetection.Signal {
	rule := candidate.rule
	seq := rule.sequence
	if len(seq.steps) == 0 {
		return nil
	}
	st, ruleState, groupKey, ok := e.sequenceCandidateState(view, candidate)
	if !ok || !e.recordSequenceStep(view, rule, st) {
		return nil
	}
	if st.StepIndex < len(seq.steps) {
		e.updateSequenceWait(rule.rule.spec.RuleID, seq, st)
		return nil
	}
	refs := appendRefs(nil, st.Refs...)
	e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
	delete(ruleState.Groups, groupKey)
	return e.signal(view.ev, rule.rule, refs, rule.rule.spec.Stage, st.Entities...)
}

func (e *Engine) sequenceCandidateState(view eventView, candidate compiledSequenceCandidate) (*cepGroupState, *cepRuleState, string, bool) {
	rule := candidate.rule
	seq := rule.sequence
	ruleState := e.cep[rule.rule.spec.RuleID]
	if ruleState == nil {
		ruleState = &cepRuleState{Groups: make(map[string]*cepGroupState)}
		e.cep[rule.rule.spec.RuleID] = ruleState
	}
	groupKey := e.compiledSequenceGroupKey(view, seq.by)
	now := view.eventTime()
	st := ruleState.Groups[groupKey]
	if st != nil && st.ExpiresAt > 0 && now > st.ExpiresAt {
		e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
		delete(ruleState.Groups, groupKey)
		e.metrics.ExpiredCEPGroups++
		st = nil
	}
	if !candidate.firstStep {
		if st == nil || st.StepIndex != candidate.stepIndex {
			return nil, nil, "", false
		}
	} else if st != nil && st.StepIndex > 0 {
		if !e.matchCompiledStep(view, seq.steps[0], &cepGroupState{Values: make(map[string]map[string]string)}) {
			return nil, nil, "", false
		}
		e.resetSequenceGroup(rule.rule.spec.RuleID, st)
	}
	if st == nil {
		e.evictCEPGroups(rule.rule.spec.RuleID, ruleState, now)
		st = &cepGroupState{Values: make(map[string]map[string]string)}
		ruleState.Groups[groupKey] = st
	}
	if st.StepIndex >= len(seq.steps) {
		e.resetSequenceGroup(rule.rule.spec.RuleID, st)
	}
	return st, ruleState, groupKey, true
}

func (e *Engine) resetSequenceGroup(ruleID string, st *cepGroupState) {
	e.deactivateSequenceWait(ruleID, st.WaitingBehavior)
	st.StepIndex = 0
	st.Refs = nil
	st.Entities = nil
	st.Values = make(map[string]map[string]string)
	st.WaitingBehavior = ""
}

func (e *Engine) recordSequenceStep(view eventView, rule compiledRule, st *cepGroupState) bool {
	seq := rule.sequence
	step := seq.steps[st.StepIndex]
	if !e.matchCompiledStep(view, step, st) {
		return false
	}
	st.Refs = appendUnique(st.Refs, view.eventID)
	st.Entities = appendUniqueEntities(st.Entities, eventEntities(view.ev)...)
	st.Entities = appendUniqueEntities(st.Entities, sequenceEvidenceEntities(view, step, st)...)
	if len(st.Refs) > e.limits.MaxCEPRefs {
		e.metrics.DroppedEventRefs += uint64(len(st.Refs) - e.limits.MaxCEPRefs)
		st.Refs = st.Refs[len(st.Refs)-e.limits.MaxCEPRefs:]
	}
	if st.Values == nil {
		st.Values = make(map[string]map[string]string)
	}
	if saved := eventFieldMapFromView(view, step.saveFields); len(saved) > 0 {
		st.Values[step.id] = saved
	}
	if st.StepIndex == 0 && seq.within > 0 {
		st.ExpiresAt = view.eventTime() + uint64(seq.within.Nanoseconds())
	}
	st.StepIndex++
	return true
}

func (e *Engine) updateSequenceWait(ruleID string, seq compiledSequence, st *cepGroupState) {
	e.deactivateSequenceWait(ruleID, st.WaitingBehavior)
	st.WaitingBehavior = seq.steps[st.StepIndex].behavior
	e.activateSequenceWait(ruleID, st.WaitingBehavior)
}

func (e *Engine) activateSequenceWait(ruleID, behavior string) {
	if ruleID == "" {
		return
	}
	if e.cepActive == nil {
		e.cepActive = make(map[string]map[string]int)
	}
	if e.cepActive[behavior] == nil {
		e.cepActive[behavior] = make(map[string]int)
	}
	e.cepActive[behavior][ruleID]++
}

func (e *Engine) deactivateSequenceWait(ruleID, behavior string) {
	if ruleID == "" || e.cepActive == nil || e.cepActive[behavior] == nil {
		return
	}
	if e.cepActive[behavior][ruleID] <= 1 {
		delete(e.cepActive[behavior], ruleID)
		if len(e.cepActive[behavior]) == 0 {
			delete(e.cepActive, behavior)
		}
		return
	}
	e.cepActive[behavior][ruleID]--
}

func (e *Engine) evictCEPGroups(ruleID string, ruleState *cepRuleState, now uint64) {
	if ruleState == nil || len(ruleState.Groups) < e.limits.MaxCEPGroups {
		return
	}
	for key, group := range ruleState.Groups {
		if group.ExpiresAt > 0 && now > group.ExpiresAt {
			e.deactivateSequenceWait(ruleID, group.WaitingBehavior)
			delete(ruleState.Groups, key)
			e.metrics.ExpiredCEPGroups++
		}
	}
	for len(ruleState.Groups) >= e.limits.MaxCEPGroups {
		for key := range ruleState.Groups {
			e.deactivateSequenceWait(ruleID, ruleState.Groups[key].WaitingBehavior)
			delete(ruleState.Groups, key)
			e.metrics.EvictedCEPGroups++
			break
		}
	}
}

func (e *Engine) recordConditionResult(matched bool) bool {
	if matched {
		e.metrics.ConditionsMatched++
	}
	return matched
}

func (e *Engine) contentValues(ref string) []string {
	if item, ok := e.refs.ContextRefs[ref]; ok {
		return item.Values
	}
	if item, ok := e.refs.IOCRefs[ref]; ok {
		return item.Values
	}
	return nil
}

func sudoCommand(argv []string) string {
	if len(argv) < 2 || filepath.Base(argv[0]) != "sudo" {
		return ""
	}
	for _, arg := range argv[1:] {
		if strings.ContainsAny(arg, "\"'") {
			return ""
		}
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			if i+1 < len(argv) {
				return filepath.Base(argv[i+1])
			}
			return ""
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return filepath.Base(arg)
		}
		if sudoOptionHasInlineValue(arg) || sudoFlagWithoutValue(arg) {
			continue
		}
		if sudoOptionNeedsValue(arg) && i+1 < len(argv) {
			i++
			continue
		}
		return ""
	}
	return ""
}

func sudoOptionHasInlineValue(arg string) bool {
	if name, _, ok := strings.Cut(arg, "="); ok && strings.HasPrefix(name, "--") {
		return sudoOptionNeedsValue(name) || name == "--preserve-env"
	}
	return len(arg) > 2 && strings.ContainsRune("CDghprTtu", rune(arg[1]))
}

func sudoOptionNeedsValue(arg string) bool {
	switch arg {
	case "-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-u",
		"--chdir", "--chroot", "--close-from", "--command-timeout", "--group",
		"--host", "--prompt", "--role", "--type", "--user":
		return true
	default:
		return false
	}
}

func sudoFlagWithoutValue(arg string) bool {
	switch arg {
	case "-A", "-b", "-E", "-H", "-k", "-n", "-P", "-S",
		"--askpass", "--background", "--non-interactive", "--preserve-env",
		"--preserve-groups", "--reset-timestamp", "--set-home", "--stdin":
		return true
	default:
		return false
	}
}

func eventEntities(ev domainevent.Event) []domaindetection.Entity {
	entities := []domaindetection.Entity{processEntity(ev)}
	if eventBehavior(ev) == "process_exec" && ev.Subject.Binary != "" {
		entities = append(entities, fileEntity(ev.Subject.Binary, "subject"))
	}
	if path := ev.Object.FilePath; path != "" {
		entities = append(entities, fileEntity(path, "object"))
	}
	if socket := ev.Object.SocketAddress; socket != "" {
		entities = append(entities, socketEntity(ev))
	}
	if containerID := ev.ContainerID; containerID != "" {
		entities = append(entities, domaindetection.Entity{Kind: "container", Key: containerID, Role: "scope"})
	}
	return entities
}

func containsString(values []string, actual string) bool {
	for _, value := range values {
		if actual == value {
			return true
		}
	}
	return false
}

func firstValue(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func compareNumber(actual, expected, op string) bool {
	a, err := strconv.ParseFloat(actual, 64)
	if err != nil {
		return false
	}
	b, err := strconv.ParseFloat(expected, 64)
	if err != nil {
		return false
	}
	switch op {
	case "gt":
		return a > b
	case "gte":
		return a >= b
	case "lt":
		return a < b
	case "lte":
		return a <= b
	default:
		return false
	}
}

func confidenceForRule(rule effectiveRule) uint32 {
	if rule.intent != nil && rule.intent.Confidence > 0 {
		return rule.intent.Confidence
	}
	if rule.spec.ResponseIntent != nil && rule.spec.ResponseIntent.Confidence > 0 {
		return rule.spec.ResponseIntent.Confidence
	}
	switch strings.ToLower(rule.severity) {
	case "critical":
		return 80
	case "high":
		return 70
	case "medium":
		return 55
	default:
		return 40
	}
}

func processEntity(ev domainevent.Event) domaindetection.Entity {
	return domaindetection.Entity{Kind: "process", Key: ev.Subject.StableID, Role: "subject"}
}

func socketEntity(ev domainevent.Event) domaindetection.Entity {
	return domaindetection.Entity{Kind: "socket", Key: ev.Object.SocketAddress, Role: "object"}
}

func fileEntity(path, role string) domaindetection.Entity {
	return domaindetection.Entity{Kind: "file", Key: path, Role: role}
}

func riskForSeverity(severity string) uint32 {
	switch strings.ToLower(severity) {
	case "critical":
		return 80
	case "high":
		return 55
	case "medium":
		return 35
	case "low":
		return 15
	default:
		return 30
	}
}

func appendRefs(base []string, refs ...string) []string {
	out := append([]string(nil), base...)
	for _, ref := range refs {
		out = appendUnique(out, ref)
	}
	return out
}

func appendUnique(items []string, item string) []string {
	if item == "" {
		return items
	}
	for _, existing := range items {
		if existing == item {
			return items
		}
	}
	return append(items, item)
}

func compact(in []*domaindetection.Signal) []*domaindetection.Signal {
	out := in[:0]
	for _, sig := range in {
		if sig != nil {
			out = append(out, sig)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
