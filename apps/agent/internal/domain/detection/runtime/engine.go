package runtime

import (
	"fmt"
	"strings"
	"time"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	detectioncompiler "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/compiler"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

const defaultMaxCEPGroups = 16384
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
	intent   *domaindetection.ResponseIntent
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
	ResponseIntent    *domaindetection.ResponseIntent
	Stage             domaindetection.SignalStage
	Mode              string
}

type ProgramInput struct {
	Rules   []RuleSpec
	Content ContentSnapshot
}

type Program struct {
	rules       map[string]effectiveRule
	refs        ContentSnapshot
	compiled    compiledRuntime
	sequence    compiledSequenceRuntime
	correlation compiledCorrelateRuntime
}

type Limits = EngineLimits
type State = Engine

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

func Compile(input ProgramInput) (Program, ApplyReport) {
	program := Program{rules: make(map[string]effectiveRule), refs: input.Content}
	report := ApplyReport{Status: "applied", Message: "detection policy applied"}
	if len(input.Rules) == 0 {
		report.Status = "rejected"
		report.Message = "detection program rejected: explicit rules are required"
		report.Details = []string{"detection program requires at least one explicit rule"}
		return program, report
	}
	rules := make([]effectiveRule, 0, len(input.Rules))
	for _, spec := range input.Rules {
		rule := effectiveRule{spec: spec, enabled: true, mode: firstNonEmpty(spec.Mode, "observe"), severity: spec.Severity, intent: spec.ResponseIntent}
		rules = append(rules, rule)
		program.rules[spec.RuleID] = rule
		report.RuleIDs = append(report.RuleIDs, rule.spec.RuleID)
	}
	errs := detectioncompiler.Validate(domainRules(rules))
	errs = append(errs, validateSignalStages(rules)...)
	errs = append(errs, validateContentRefs(rules, input.Content)...)
	if len(errs) > 0 {
		report.Status = "rejected"
		report.Message = "detection policy rejected"
		report.Details = append(report.Details, errs...)
		report.Warnings = append(report.Warnings, errs...)
		return program, report
	}
	program.compiled = compileRuntime(rules, input.Content)
	program.sequence = compileSequenceRuntime(rules, input.Content)
	program.correlation = compileCorrelateRuntime(rules, input.Content)
	return program, report
}

func validateSignalStages(rules []effectiveRule) []string {
	var errs []string
	for _, rule := range rules {
		if rule.spec.Stage != domaindetection.SignalStageCandidate && rule.spec.Stage != domaindetection.SignalStageConclusion {
			errs = append(errs, fmt.Sprintf("rule %s requires candidate or conclusion signal stage", rule.spec.RuleID))
		}
	}
	return errs
}

func NewState(program Program, limits Limits) *State {
	limits = normalizeLimits(limits)
	return &Engine{rules: program.rules, cep: make(map[string]*cepRuleState), cepActive: make(map[string]map[string]int), correlate: make(map[string]*correlateRuleState), suppression: make(map[string]time.Time), limits: limits, refs: program.refs, compiled: program.compiled, sequence: program.sequence, correlation: program.correlation}
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

func (e *Engine) Process(ev domainevent.Event) []*domaindetection.Signal {
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
	e.metrics.EmittedSignals += uint64(len(detected))
	e.metrics.ProcessNanosTotal += uint64(time.Since(start).Nanoseconds())
	return detected
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

func (e *Engine) signal(ev domainevent.Event, rule effectiveRule, refs []string, stage domaindetection.SignalStage, entities ...domaindetection.Entity) *domaindetection.Signal {
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
		Stage:        stage,
		DetectorKind: domaindetection.DetectorKindRule,
		Labels:       cloneLabels(ev.Labels),
		ContextRefs:  e.signalContentRefs(rule.spec.ContextRefs, e.refs.ContextRefs),
		IOCRefs:      e.signalContentRefs(rule.spec.IOCRefs, e.refs.IOCRefs),
	}
	if stage == domaindetection.SignalStageConclusion || rule.intent != nil {
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
	if stage == domaindetection.SignalStageConclusion {
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
