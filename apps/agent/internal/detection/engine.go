package detection

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	contractadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	detectioncompiler "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/compiler"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/eventmodel"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

const defaultMaxCEPGroups = 4096
const defaultMaxCEPRefs = 128
const maxSuppressionKeys = 8192

type Engine struct {
	nextID      uint64
	rules       map[string]effectiveRule
	cep         map[string]*cepRuleState
	cepActive   map[string]map[string]int
	correlate   map[string]*correlateRuleState
	suppression map[string]time.Time
	limits      EngineLimits
	metrics     Metrics
	refs        ContentSnapshot
	compiled    compiledRuntime
	sequence    compiledSequenceRuntime
	correlation compiledCorrelateRuntime
}

type EngineLimits struct {
	MaxCEPGroups int
	MaxCEPRefs   int
}

type Metrics struct {
	EventsProcessed      uint64
	EventsByBehavior     map[string]uint64
	CEPRulesScanned      uint64
	CEPRulesEvaluated    uint64
	ConditionsEvaluated  uint64
	ConditionsMatched    uint64
	FieldReads           uint64
	ProcessNanosTotal    uint64
	ActiveCEPGroups      uint64
	EvictedCEPGroups     uint64
	ExpiredCEPGroups     uint64
	DroppedEventRefs     uint64
	SuppressionEvictions uint64
	CEPEvalErrors        uint64
	EmittedSignals       uint64
}

type ContentSnapshot struct {
	ContextRefs map[string]ContentRef
	IOCRefs     map[string]ContentRef
	Rules       []RuleSpec
}

type ContentRef struct {
	Ref     string
	Version string
	Digest  string
	Values  []string
}

type effectiveRule struct {
	spec     RuleSpec
	enabled  bool
	mode     string
	severity string
	intent   *policymodel.ResponseIntentRef
	params   map[string]string
}

type RuleSpec struct {
	RuleID            string
	Version           uint64
	RuleSetRef        string
	Where             string
	Severity          string
	Runtime           string
	RuntimeType       string
	Expr              ExprSpec
	Sequence          SequenceSpec
	Correlate         CorrelateSpec
	Suppression       SuppressionSpec
	RequiredEvents    []RequiredEventSpec
	RequiredBehaviors []string
	ContextRefs       []string
	IOCRefs           []string
	ResponseIntent    *policymodel.ResponseIntentRef
	Terminal          *bool
}

type RequiredEventSpec struct {
	Behavior string
	Fields   []string
}

type ExprSpec struct {
	Conditions     []ConditionSpec
	ConditionGroup *ConditionNodeSpec
}

type ConditionNodeSpec struct {
	All       []ConditionNodeSpec
	Any       []ConditionNodeSpec
	Not       *ConditionNodeSpec
	Condition *ConditionSpec
}

type SequenceSpec struct {
	Within time.Duration
	By     []string
	Steps  []StepSpec
}

type CorrelateSpec struct {
	Within     time.Duration
	WithinText string
	By         []string
	Facts      []FactSpec
}

type FactSpec struct {
	ID             string
	Event          string
	Events         []string
	Conditions     []ConditionSpec
	ConditionGroup *ConditionNodeSpec
}

type SuppressionSpec struct {
	Within time.Duration
	By     []string
}

type StepSpec struct {
	ID             string
	Behavior       string
	Conditions     []ConditionSpec
	ConditionGroup *ConditionNodeSpec
}

type ConditionSpec struct {
	Field     string
	Op        string
	Value     string
	Values    []string
	Ref       string
	Step      string
	StepField string
}

type cepRuleState struct {
	Groups map[string]*cepGroupState
}

type cepGroupState struct {
	StepIndex       int
	Refs            []string
	Entities        []domaindetection.Entity
	Values          map[string]map[string]string
	ExpiresAt       uint64
	WaitingBehavior string
}

type ApplyReport struct {
	Status   string         `json:"status"`
	Message  string         `json:"message"`
	Details  []string       `json:"details,omitempty"`
	RuleIDs  []string       `json:"rule_ids,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
	Coverage CoverageReport `json:"coverage,omitempty"`
}

type CoverageReport struct {
	Status   string         `json:"status"`
	Rules    []RuleCoverage `json:"rules,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

type RuleCoverage struct {
	RuleID            string   `json:"rule_id"`
	Status            string   `json:"status"`
	RequiredBehaviors []string `json:"required_behaviors,omitempty"`
	RequiredFields    []string `json:"required_fields,omitempty"`
	MissingBehaviors  []string `json:"missing_behaviors,omitempty"`
	MissingFields     []string `json:"missing_fields,omitempty"`
}

func New(policy *policymodel.DetectionPolicy) (*Engine, ApplyReport) {
	return NewWithInputs(policy, contract.CollectionIntent{})
}

func NewWithInputs(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent) (*Engine, ApplyReport) {
	return NewWithRuntime(policy, collection, ContentSnapshot{})
}

func NewWithRuntime(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content ContentSnapshot) (*Engine, ApplyReport) {
	return NewWithRuntimeLimits(policy, collection, content, EngineLimits{})
}

func NewWithRuntimeLimits(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content ContentSnapshot, limits EngineLimits) (*Engine, ApplyReport) {
	normalized := policymodel.DefaultDetectionPolicy()
	if policy != nil {
		tmp := policymodel.NormalizeDetectionPolicy(*policy)
		normalized = &tmp
	}
	limits = normalizeLimits(limits)
	engine := &Engine{
		rules:       make(map[string]effectiveRule),
		cep:         make(map[string]*cepRuleState),
		cepActive:   make(map[string]map[string]int),
		correlate:   make(map[string]*correlateRuleState),
		suppression: make(map[string]time.Time),
		limits:      limits,
		refs:        content,
	}
	report := ApplyReport{Status: "applied", Message: "detection policy applied"}
	if len(normalized.RuleSets) == 0 {
		report.Status = "rejected"
		report.Message = "detection policy rejected: explicit ruleset is required"
		report.Details = []string{"detection policy requires at least one explicit ruleset"}
		return engine, report
	}
	if errs := validateRuleSelection(normalized, content); len(errs) > 0 {
		report.Status = "rejected"
		report.Message = "detection policy rejected"
		report.Details = errs
		return engine, report
	}
	rules := resolveRules(normalized, content)
	for _, rule := range rules {
		engine.rules[rule.spec.RuleID] = rule
		report.RuleIDs = append(report.RuleIDs, rule.spec.RuleID)
	}
	errs := detectioncompiler.Validate(domainRules(rules))
	errs = append(errs, validateContentRefs(rules, content)...)
	if len(errs) > 0 {
		report.Status = "rejected"
		report.Message = "detection policy rejected"
		report.Details = append(report.Details, errs...)
		report.Warnings = append(report.Warnings, errs...)
		return engine, report
	}
	engine.compiled = compileRuntime(rules, content)
	engine.sequence = compileSequenceRuntime(rules, content)
	engine.correlation = compileCorrelateRuntime(rules, content)
	report.Coverage = CheckCoverageWithContent(normalized, collection, content)
	report.Warnings = append(report.Warnings, report.Coverage.Warnings...)
	if len(report.Warnings) > 0 {
		report.Status = "degraded"
		report.Message = "detection policy applied with missing collection inputs"
		report.Details = append(report.Details, report.Warnings...)
	}
	return engine, report
}

func validateContentRefs(rules []effectiveRule, content ContentSnapshot) []string {
	var errs []string
	for _, rule := range rules {
		for _, ref := range rule.spec.ContextRefs {
			if _, ok := content.ContextRefs[ref]; !ok {
				errs = append(errs, fmt.Sprintf("rule %s requires missing context ref %s", rule.spec.RuleID, ref))
			}
		}
		for _, ref := range rule.spec.IOCRefs {
			if _, ok := content.IOCRefs[ref]; !ok {
				errs = append(errs, fmt.Sprintf("rule %s requires missing IOC ref %s", rule.spec.RuleID, ref))
			}
		}
	}
	return errs
}

func validateRuleSelection(policy *policymodel.DetectionPolicy, content ContentSnapshot) []string {
	specs := content.Rules
	available := make(map[string]bool)
	for _, spec := range specs {
		available[spec.RuleSetRef] = true
	}
	var errs []string
	for _, ref := range policy.RuleSets {
		if ref.Ref != "" && (ref.Enabled == nil || *ref.Enabled) && !available[ref.Ref] {
			errs = append(errs, fmt.Sprintf("ruleset %s is not available", ref.Ref))
		}
	}
	seen := make(map[string]bool)
	for _, rule := range resolveRules(policy, content) {
		if seen[rule.spec.RuleID] {
			errs = append(errs, fmt.Sprintf("duplicate rule id %s", rule.spec.RuleID))
		}
		seen[rule.spec.RuleID] = true
	}
	return errs
}

func normalizeLimits(limits EngineLimits) EngineLimits {
	if limits.MaxCEPGroups <= 0 {
		limits.MaxCEPGroups = defaultMaxCEPGroups
	}
	if limits.MaxCEPRefs <= 0 {
		limits.MaxCEPRefs = defaultMaxCEPRefs
	}
	return limits
}

func (e *Engine) Metrics() Metrics {
	if e == nil {
		return Metrics{}
	}
	metrics := e.metrics
	if len(metrics.EventsByBehavior) > 0 {
		metrics.EventsByBehavior = cloneMetricsMap(metrics.EventsByBehavior)
	}
	var active uint64
	for _, ruleState := range e.cep {
		active += uint64(len(ruleState.Groups))
	}
	for _, ruleState := range e.correlate {
		active += uint64(len(ruleState.Groups))
	}
	metrics.ActiveCEPGroups = active
	return metrics
}

func (e *Engine) Process(ev domainevent.Event) []*signalv1.Signal {
	if e == nil || !ev.SubjectPresent {
		return nil
	}
	start := time.Now()
	view := newEventView(ev)
	behavior := view.behavior
	e.metrics.EventsProcessed++
	if e.metrics.EventsByBehavior == nil {
		e.metrics.EventsByBehavior = make(map[string]uint64)
	}
	e.metrics.EventsByBehavior[behavior]++
	detected := compact(e.detectCEPRules(view))
	var out []*signalv1.Signal
	for _, signal := range detected {
		out = append(out, contractadapter.Signal(*signal))
	}
	e.metrics.EmittedSignals += uint64(len(detected))
	e.metrics.ProcessNanosTotal += uint64(time.Since(start).Nanoseconds())
	return out
}

func cloneMetricsMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func eventBehavior(ev domainevent.Event) string {
	if behavior := strings.TrimSpace(ev.Behavior); behavior != "" {
		return strings.ToLower(behavior)
	}
	return ""
}

func eventWallTime(ev domainevent.Event) time.Time {
	if ev.OccurredAtNS > 0 {
		return time.Unix(0, int64(ev.OccurredAtNS)).UTC()
	}
	if ev.MonoNS > 0 {
		return time.Unix(0, int64(ev.MonoNS)).UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) suppressSignal(key string, now time.Time, window time.Duration) bool {
	if e == nil || key == "" || window <= 0 {
		return false
	}
	if expiresAt, ok := e.suppression[key]; ok && now.Before(expiresAt) {
		return true
	}
	if len(e.suppression) >= maxSuppressionKeys {
		for got, expiresAt := range e.suppression {
			if !expiresAt.After(now) {
				delete(e.suppression, got)
			}
		}
	}
	for len(e.suppression) >= maxSuppressionKeys {
		for got := range e.suppression {
			delete(e.suppression, got)
			e.metrics.SuppressionEvictions++
			break
		}
	}
	e.suppression[key] = now.Add(window)
	return false
}

func (e *Engine) rule(id string) (effectiveRule, bool) {
	rule, ok := e.rules[id]
	return rule, ok && rule.enabled
}

func (e *Engine) signal(ev domainevent.Event, rule effectiveRule, refs []string, terminal bool, entities ...domaindetection.Entity) *domaindetection.Signal {
	refs = appendRefs(nil, refs...)
	if len(refs) == 0 {
		refs = []string{ev.ID}
	}
	e.nextID++
	sig := domaindetection.Signal{
		ID:           fmt.Sprintf("sig-%020d", e.nextID),
		Name:         rule.spec.RuleID,
		RuleID:       rule.spec.RuleID,
		RuleVersion:  rule.spec.Version,
		RuleSetRef:   rule.spec.RuleSetRef,
		Where:        domaindetection.SignalWhereEndpoint,
		BaseRisk:     riskForSeverity(rule.severity),
		Severity:     rule.severity,
		Confidence:   confidenceForRule(rule),
		Mode:         rule.mode,
		LocalRarity:  1,
		GlobalRarity: 1,
		LineageID:    ev.LineageID,
		Entities:     entities,
		EventRefs:    refs,
		Terminal:     terminal,
		Labels:       cloneLabels(ev.Labels),
		ContextRefs:  e.signalContentRefs(rule.spec.ContextRefs, e.refs.ContextRefs),
		IOCRefs:      e.signalContentRefs(rule.spec.IOCRefs, e.refs.IOCRefs),
	}
	if terminal || rule.intent != nil {
		intent := rule.intent
		if intent == nil {
			intent = rule.spec.ResponseIntent
		}
		if intent != nil && intent.Action != "" {
			sig.ResponseIntent = &domaindetection.ResponseIntent{
				Action: intent.Action, Confidence: intent.Confidence, Reason: intent.Reason,
			}
		}
	}
	if terminal {
		sig.Evidence = &domaindetection.Evidence{
			ID:        "evb-" + sig.ID,
			EventRefs: append([]string(nil), refs...),
			RawRefs:   []string{ev.RawRef},
			Entities:  entities,
			Summary:   fmt.Sprintf("rule=%s version=%d ruleset=%s severity=%s", rule.spec.RuleID, rule.spec.Version, rule.spec.RuleSetRef, rule.severity),
		}
	}
	return &sig
}

func cloneLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (e *Engine) signalContentRefs(refs []string, resolved map[string]ContentRef) []domaindetection.ContentRef {
	out := make([]domaindetection.ContentRef, 0, len(refs))
	for _, ref := range refs {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		item := resolved[ref]
		out = append(out, domaindetection.ContentRef{Ref: item.Ref, Version: item.Version, Digest: item.Digest})
	}
	return out
}

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
				out = append(out, e.signal(view.ev, rule.rule, []string{view.eventID}, rule.rule.terminal(false), eventEntities(view.ev)...))
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

func (r effectiveRule) terminal(defaultValue bool) bool {
	if r.spec.Terminal == nil {
		return defaultValue
	}
	return *r.spec.Terminal
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
			return nil
		}
	} else if st != nil && st.StepIndex > 0 {
		if !e.matchCompiledStep(view, seq.steps[0], &cepGroupState{Values: make(map[string]map[string]string)}) {
			return nil
		}
		e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
		st.StepIndex = 0
		st.Refs = nil
		st.Entities = nil
		st.Values = make(map[string]map[string]string)
		st.WaitingBehavior = ""
	}
	if st == nil {
		e.evictCEPGroups(rule.rule.spec.RuleID, ruleState, now)
		st = &cepGroupState{Values: make(map[string]map[string]string)}
		ruleState.Groups[groupKey] = st
	}
	if st.StepIndex >= len(seq.steps) {
		e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
		st.StepIndex = 0
		st.Refs = nil
		st.Entities = nil
		st.Values = make(map[string]map[string]string)
		st.WaitingBehavior = ""
	}
	step := seq.steps[st.StepIndex]
	if !e.matchCompiledStep(view, step, st) {
		return nil
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
		st.ExpiresAt = now + uint64(seq.within.Nanoseconds())
	}
	st.StepIndex++
	if st.StepIndex < len(seq.steps) {
		e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
		st.WaitingBehavior = seq.steps[st.StepIndex].behavior
		e.activateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
		return nil
	}
	refs := appendRefs(nil, st.Refs...)
	e.deactivateSequenceWait(rule.rule.spec.RuleID, st.WaitingBehavior)
	delete(ruleState.Groups, groupKey)
	return e.signal(view.ev, rule.rule, refs, rule.rule.terminal(true), st.Entities...)
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
	if eventBehavior(ev) == eventmodel.BehaviorProcessExec.String() && ev.Subject.Binary != "" {
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

func resolveRules(policy *policymodel.DetectionPolicy, content ContentSnapshot) []effectiveRule {
	specs := content.Rules
	enabledRuleSets := map[string]bool{}
	for _, ref := range policy.RuleSets {
		if ref.Ref == "" {
			continue
		}
		enabled := true
		if ref.Enabled != nil {
			enabled = *ref.Enabled
		}
		enabledRuleSets[ref.Ref] = enabled
	}
	overrides := map[string]policymodel.RuleOverride{}
	for _, override := range policy.RuleOverrides {
		if override.RuleID != "" {
			overrides[override.RuleID] = override
		}
	}
	var out []effectiveRule
	for _, spec := range specs {
		if !enabledRuleSets[spec.RuleSetRef] {
			continue
		}
		rule := effectiveRule{
			spec:     spec,
			enabled:  true,
			mode:     firstNonEmpty(policy.Mode, "observe"),
			severity: spec.Severity,
			intent:   spec.ResponseIntent,
		}
		if override, ok := overrides[spec.RuleID]; ok {
			if override.Enabled != nil {
				rule.enabled = *override.Enabled
			}
			if override.Mode != "" {
				rule.mode = override.Mode
			}
			if override.Severity != "" {
				rule.severity = override.Severity
			}
			if override.ResponseIntent != nil {
				rule.intent = override.ResponseIntent
			}
			rule.params = override.Params
		}
		if rule.enabled {
			out = append(out, rule)
		}
	}
	return out
}

func CheckDependencies(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent) []string {
	return CheckDependenciesWithContent(policy, collection, ContentSnapshot{})
}

func CheckDependenciesWithContent(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content ContentSnapshot) []string {
	return CheckCoverageWithContent(policy, collection, content).Warnings
}

func CheckCoverage(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent) CoverageReport {
	return CheckCoverageWithContent(policy, collection, ContentSnapshot{})
}

func CheckCoverageWithContent(policy *policymodel.DetectionPolicy, collection contract.CollectionIntent, content ContentSnapshot) CoverageReport {
	if policy == nil {
		tmp := policymodel.DefaultDetectionPolicy()
		policy = tmp
	}
	collectedBehaviors := map[string]bool{}
	for _, behavior := range collection.Behaviors {
		behavior = eventmodel.NormalizeBehavior(behavior).String()
		if behavior != "" {
			collectedBehaviors[behavior] = true
		}
	}
	if len(collectedBehaviors) == 0 {
		return CoverageReport{Status: "unknown"}
	}
	report := CoverageReport{Status: "covered"}
	for _, rule := range resolveRules(policy, content) {
		coverage := RuleCoverage{RuleID: rule.spec.RuleID, Status: "covered"}
		for _, behavior := range rule.spec.RequiredBehaviors {
			behavior = eventmodel.NormalizeBehavior(behavior).String()
			if behavior == "" {
				continue
			}
			coverage.RequiredBehaviors = appendUnique(coverage.RequiredBehaviors, behavior)
			if !collectedBehaviors[behavior] {
				coverage.MissingBehaviors = appendUnique(coverage.MissingBehaviors, behavior)
			}
		}
		availableFields := availableFieldsForCollection(collection)
		for _, req := range rule.spec.RequiredEvents {
			behavior := eventmodel.NormalizeBehavior(req.Behavior).String()
			if behavior != "" {
				coverage.RequiredBehaviors = appendUnique(coverage.RequiredBehaviors, behavior)
				if !collectedBehaviors[behavior] {
					coverage.MissingBehaviors = appendUnique(coverage.MissingBehaviors, behavior)
				}
			}
			for _, field := range req.Fields {
				if field == "" {
					continue
				}
				requiredField := fmt.Sprintf("%s:%s", firstNonEmpty(behavior, req.Behavior, "event"), field)
				coverage.RequiredFields = appendUnique(coverage.RequiredFields, requiredField)
				if !availableFields[field] {
					coverage.MissingFields = appendUnique(coverage.MissingFields, requiredField)
				}
			}
		}
		if len(coverage.MissingBehaviors) > 0 || len(coverage.MissingFields) > 0 {
			coverage.Status = "missing_inputs"
			report.Status = "degraded"
			missing := append([]string(nil), coverage.MissingBehaviors...)
			missing = append(missing, coverage.MissingFields...)
			report.Warnings = append(report.Warnings, fmt.Sprintf("rule %s missing collection inputs: %s", rule.spec.RuleID, strings.Join(missing, ",")))
		}
		report.Rules = append(report.Rules, coverage)
	}
	return report
}

func availableFieldsForCollection(collection contract.CollectionIntent) map[string]bool {
	if len(collection.Capabilities) > 0 {
		return availableFieldsFromCapabilities(collection)
	}
	fields := map[string]bool{
		"event.id":       true,
		"event.behavior": true,
		"lineage_id":     true,
		"scope.type":     true,
		"scope.selector": true,
		"container.id":   true,
		"container_id":   true,
		"cgroup":         true,
	}
	addProcess := func() {
		for _, field := range []string{"process.stable_id", "process.id", "process.binary", "process.argv", "process.uid", "process.pid", "pid", "parent.stable_id", "parent.id"} {
			fields[field] = true
		}
	}
	if len(collection.Behaviors) == 0 {
		for _, field := range []string{"file.path", "object.file_path", "socket.addr", "object.socket_addr", "socket.port", "socket"} {
			fields[field] = true
		}
		addProcess()
		return fields
	}
	behaviors := map[string]bool{}
	for _, behavior := range collection.Behaviors {
		behaviors[eventmodel.NormalizeBehavior(behavior).String()] = true
	}
	if behaviors[eventmodel.BehaviorProcessExec.String()] || behaviors[eventmodel.BehaviorProcessFork.String()] || behaviors[eventmodel.BehaviorProcessExit.String()] {
		addProcess()
	}
	if behaviors[eventmodel.BehaviorFileOpen.String()] || behaviors[eventmodel.BehaviorFileRead.String()] || behaviors[eventmodel.BehaviorFileWrite.String()] || behaviors[eventmodel.BehaviorFileChmod.String()] {
		addProcess()
		fields["file.path"] = true
		fields["object.file_path"] = true
	}
	if behaviors[eventmodel.BehaviorNetworkConnect.String()] {
		addProcess()
		fields["socket.addr"] = true
		fields["object.socket_addr"] = true
		fields["socket.port"] = true
		fields["socket"] = true
	}
	return fields
}

func availableFieldsFromCapabilities(collection contract.CollectionIntent) map[string]bool {
	fields := map[string]bool{}
	behaviors := map[string]bool{}
	for _, behavior := range collection.Behaviors {
		behavior = eventmodel.NormalizeBehavior(behavior).String()
		if behavior != "" {
			behaviors[behavior] = true
		}
	}
	for _, behavior := range collection.Capabilities {
		if len(behaviors) > 0 && !behaviors[eventmodel.NormalizeBehavior(behavior.Behavior).String()] {
			continue
		}
		for _, field := range behavior.Fields {
			if field != "" {
				fields[field] = true
			}
		}
	}
	return fields
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
