package detection

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	detectioncompiler "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/compiler"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/eventmodel"
)

type compiledRuntime struct {
	byBehavior       map[string][]compiledRule
	behaviorAgnostic []compiledRule
}

type compiledSequenceRuntime struct {
	firstByBehavior  map[string][]compiledSequenceCandidate
	nextByBehavior   map[string][]compiledSequenceCandidate
	behaviorAgnostic []compiledSequenceCandidate
}

type compiledRuleKind uint8

const (
	compiledRuleExpr compiledRuleKind = iota + 1
	compiledRuleSequence
)

type compiledRule struct {
	rule     effectiveRule
	kind     compiledRuleKind
	expr     compiledExpr
	sequence compiledSequence
}

type compiledExpr struct {
	conditions     []compiledCondition
	conditionGroup *compiledConditionNode
	suppression    compiledSuppression
}

type compiledSuppression struct {
	within time.Duration
	by     []fieldID
}

type compiledSequence struct {
	within time.Duration
	by     []fieldID
	steps  []compiledStep
}

type compiledStep struct {
	id             string
	behavior       string
	conditions     []compiledCondition
	conditionGroup *compiledConditionNode
	saveFields     []fieldID
}

type compiledSequenceCandidate struct {
	rule      compiledRule
	stepIndex int
	firstStep bool
}

type conditionOp = detectioncompiler.Operator

const (
	opEq       = detectioncompiler.OperatorEqual
	opNeq      = detectioncompiler.OperatorNotEqual
	opContains = detectioncompiler.OperatorContains
	opPrefix   = detectioncompiler.OperatorPrefix
	opSuffix   = detectioncompiler.OperatorSuffix
	opIn       = detectioncompiler.OperatorIn
	opNotIn    = detectioncompiler.OperatorNotIn
	opSameAs   = detectioncompiler.OperatorSameAs
	opExists   = detectioncompiler.OperatorExists
	opGT       = detectioncompiler.OperatorGreaterThan
	opGTE      = detectioncompiler.OperatorGreaterThanOrEqual
	opLT       = detectioncompiler.OperatorLessThan
	opLTE      = detectioncompiler.OperatorLessThanOrEqual
)

type compiledCondition struct {
	field     fieldID
	op        conditionOp
	values    []string
	matcher   matcher.Matcher
	step      string
	stepField fieldID
	cost      int
}

type fieldID = detectioncompiler.Field

const (
	fieldUnknown            = detectioncompiler.FieldUnknown
	fieldEventID            = detectioncompiler.FieldEventID
	fieldBehavior           = detectioncompiler.FieldBehavior
	fieldLineageID          = detectioncompiler.FieldLineageID
	fieldProcessStableID    = detectioncompiler.FieldProcessStableID
	fieldProcessBinary      = detectioncompiler.FieldProcessBinary
	fieldProcessBinaryName  = detectioncompiler.FieldProcessBinaryName
	fieldProcessArgv        = detectioncompiler.FieldProcessArgv
	fieldProcessSudoCommand = detectioncompiler.FieldProcessSudoCommand
	fieldProcessUID         = detectioncompiler.FieldProcessUID
	fieldProcessPID         = detectioncompiler.FieldProcessPID
	fieldParentStableID     = detectioncompiler.FieldParentStableID
	fieldFilePath           = detectioncompiler.FieldFilePath
	fieldSocketAddr         = detectioncompiler.FieldSocketAddr
	fieldSocketPort         = detectioncompiler.FieldSocketPort
	fieldSocket             = detectioncompiler.FieldSocket
	fieldScopeType          = detectioncompiler.FieldScopeType
	fieldScopeSelector      = detectioncompiler.FieldScopeSelector
	fieldContainerID        = detectioncompiler.FieldContainerID
	fieldCgroup             = detectioncompiler.FieldCgroup
)

type eventView struct {
	ev                 *eventv1.CanonicalEvent
	eventID            string
	behavior           string
	lineageID          string
	processStableID    string
	processBinary      string
	processBinaryName  string
	processArgv        string
	processSudoCommand string
	processUID         string
	processPID         string
	parentStableID     string
	filePath           string
	socketAddr         string
	socketPort         string
	socket             string
	scopeType          string
	scopeSelector      string
	containerID        string
	cgroup             string
	occurredAtNs       uint64
	monoNs             uint64
}

func compileRuntime(rules []effectiveRule, content ContentSnapshot) compiledRuntime {
	rt := compiledRuntime{byBehavior: map[string][]compiledRule{}}
	for _, rule := range rules {
		if !rule.enabled || rule.runtimeType() != "expr" {
			continue
		}
		compiled := compileRule(rule, content)
		if compiled.kind == 0 {
			continue
		}
		behaviors := compiled.behaviors()
		if len(behaviors) == 0 {
			rt.behaviorAgnostic = append(rt.behaviorAgnostic, compiled)
			continue
		}
		for _, behavior := range behaviors {
			rt.byBehavior[behavior] = append(rt.byBehavior[behavior], compiled)
		}
	}
	return rt
}

func compileSequenceRuntime(rules []effectiveRule, content ContentSnapshot) compiledSequenceRuntime {
	rt := compiledSequenceRuntime{
		firstByBehavior: map[string][]compiledSequenceCandidate{},
		nextByBehavior:  map[string][]compiledSequenceCandidate{},
	}
	for _, rule := range rules {
		if !rule.enabled || rule.runtimeType() != "sequence" {
			continue
		}
		compiled := compileRule(rule, content)
		if compiled.kind != compiledRuleSequence || len(compiled.sequence.steps) == 0 {
			continue
		}
		first := compiled.sequence.steps[0]
		if first.behavior == "" {
			rt.behaviorAgnostic = append(rt.behaviorAgnostic, compiledSequenceCandidate{rule: compiled, firstStep: true})
		} else {
			rt.firstByBehavior[first.behavior] = append(rt.firstByBehavior[first.behavior], compiledSequenceCandidate{rule: compiled, firstStep: true})
		}
		for i := 1; i < len(compiled.sequence.steps); i++ {
			step := compiled.sequence.steps[i]
			candidate := compiledSequenceCandidate{rule: compiled, stepIndex: i}
			if step.behavior == "" {
				rt.behaviorAgnostic = append(rt.behaviorAgnostic, candidate)
			} else {
				rt.nextByBehavior[step.behavior] = append(rt.nextByBehavior[step.behavior], candidate)
			}
		}
	}
	return rt
}

func compileRule(rule effectiveRule, content ContentSnapshot) compiledRule {
	switch rule.runtimeType() {
	case "expr":
		return compiledRule{
			rule: rule,
			kind: compiledRuleExpr,
			expr: compiledExpr{
				conditions:     compileConditions(rule.spec.Expr.Conditions, content),
				conditionGroup: compileConditionNode(rule.spec.Expr.ConditionGroup, content),
				suppression: compiledSuppression{
					within: rule.spec.Suppression.Within,
					by:     compileFields(rule.spec.Suppression.By),
				},
			},
		}
	case "sequence":
		steps := make([]compiledStep, 0, len(rule.spec.Sequence.Steps))
		for _, step := range rule.spec.Sequence.Steps {
			steps = append(steps, compiledStep{
				id:             strings.TrimSpace(step.ID),
				behavior:       eventmodel.NormalizeBehavior(step.Behavior).String(),
				conditions:     compileConditions(step.Conditions, content),
				conditionGroup: compileConditionNode(step.ConditionGroup, content),
			})
		}
		steps = attachSequenceSaveFields(steps)
		return compiledRule{
			rule: rule,
			kind: compiledRuleSequence,
			sequence: compiledSequence{
				within: rule.spec.Sequence.Within,
				by:     compileFields(rule.spec.Sequence.By),
				steps:  steps,
			},
		}
	default:
		return compiledRule{}
	}
}

func attachSequenceSaveFields(steps []compiledStep) []compiledStep {
	stepIndex := make(map[string]int, len(steps))
	for i, step := range steps {
		if step.id != "" {
			stepIndex[step.id] = i
		}
	}
	seen := make([]map[fieldID]bool, len(steps))
	for i := range seen {
		seen[i] = map[fieldID]bool{}
	}
	for _, step := range steps {
		conditions := append([]compiledCondition(nil), step.conditions...)
		conditions = appendCompiledNodeConditions(conditions, step.conditionGroup)
		for _, cond := range conditions {
			if cond.op != opSameAs || cond.step == "" {
				continue
			}
			idx, ok := stepIndex[cond.step]
			if !ok {
				continue
			}
			seen[idx][cond.stepField] = true
		}
	}
	for i := range steps {
		for field := range seen[i] {
			steps[i].saveFields = append(steps[i].saveFields, field)
		}
		sort.Slice(steps[i].saveFields, func(a, b int) bool {
			return steps[i].saveFields[a] < steps[i].saveFields[b]
		})
	}
	return steps
}

func (r compiledRule) behaviors() []string {
	seen := map[string]bool{}
	var out []string
	add := func(behavior string) {
		behavior = eventmodel.NormalizeBehavior(behavior).String()
		if behavior == "" || seen[behavior] {
			return
		}
		seen[behavior] = true
		out = append(out, behavior)
	}
	if r.kind == compiledRuleSequence {
		for _, step := range r.sequence.steps {
			add(step.behavior)
		}
		return out
	}
	for _, behavior := range r.rule.spec.RequiredBehaviors {
		add(behavior)
	}
	for _, event := range r.rule.spec.RequiredEvents {
		add(event.Behavior)
	}
	return out
}

func (rt compiledRuntime) rulesForBehavior(behavior string) []compiledRule {
	if len(rt.behaviorAgnostic) == 0 {
		return rt.byBehavior[behavior]
	}
	out := make([]compiledRule, 0, len(rt.behaviorAgnostic)+len(rt.byBehavior[behavior]))
	out = append(out, rt.byBehavior[behavior]...)
	out = append(out, rt.behaviorAgnostic...)
	return out
}

func (rt compiledSequenceRuntime) candidatesForBehavior(behavior string, active map[string]map[string]int) []compiledSequenceCandidate {
	candidates := rt.firstByBehavior[behavior]
	if len(rt.nextByBehavior[behavior]) > 0 {
		activeRules := active[behavior]
		if len(activeRules) > 0 {
			for _, candidate := range rt.nextByBehavior[behavior] {
				if activeRules[candidate.rule.rule.spec.RuleID] > 0 {
					candidates = append(candidates, candidate)
				}
			}
		}
	}
	if len(rt.behaviorAgnostic) == 0 {
		return candidates
	}
	out := make([]compiledSequenceCandidate, 0, len(rt.behaviorAgnostic)+len(candidates))
	out = append(out, candidates...)
	out = append(out, rt.behaviorAgnostic...)
	return out
}

func compileConditions(conditions []ConditionSpec, content ContentSnapshot) []compiledCondition {
	out := make([]compiledCondition, 0, len(conditions))
	for _, cond := range conditions {
		values := append([]string(nil), cond.Values...)
		if cond.Value != "" {
			values = append(values, cond.Value)
		}
		if cond.Ref != "" {
			values = append(values, contentValuesFromSnapshot(content, cond.Ref)...)
		}
		op := compileOp(cond.Op)
		compiled := compiledCondition{
			field:     compileField(cond.Field),
			op:        op,
			values:    normalizeConditionValues(values),
			matcher:   compileMatcher(op, values),
			step:      strings.TrimSpace(cond.Step),
			stepField: compileField(firstNonEmpty(cond.StepField, cond.Field)),
		}
		compiled.cost = conditionCost(compiled)
		out = append(out, compiled)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].cost < out[j].cost
	})
	return out
}

func compileCondition(cond ConditionSpec, content ContentSnapshot) compiledCondition {
	compiled := compileConditions([]ConditionSpec{cond}, content)
	if len(compiled) == 0 {
		return compiledCondition{}
	}
	return compiled[0]
}

func conditionCost(cond compiledCondition) int {
	cost := 10
	switch cond.op {
	case opExists:
		cost = 1
	case opEq, opIn, opNeq, opNotIn:
		cost = 2
	case opGT, opGTE, opLT, opLTE:
		cost = 3
	case opSameAs:
		cost = 4
	case opPrefix, opSuffix:
		cost = 5
	case opContains:
		cost = 8
	default:
		cost = 20
	}
	switch cond.field {
	case fieldProcessArgv:
		cost += 4
	case fieldSocketAddr, fieldSocketPort:
		cost += 1
	}
	return cost
}

func compileMatcher(op conditionOp, values []string) matcher.Matcher {
	switch op {
	case opEq, opIn, opNeq, opNotIn:
		return matcher.NewExact(values)
	case opPrefix:
		return matcher.NewPrefix(values)
	case opSuffix:
		return matcher.NewSuffix(values)
	case opContains:
		return matcher.NewContains(values)
	default:
		return nil
	}
}

func normalizeConditionValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func contentValuesFromSnapshot(content ContentSnapshot, ref string) []string {
	if item, ok := content.ContextRefs[ref]; ok {
		return item.Values
	}
	if item, ok := content.IOCRefs[ref]; ok {
		return item.Values
	}
	return nil
}

func compileFields(fields []string) []fieldID {
	if len(fields) == 0 {
		return []fieldID{fieldLineageID}
	}
	out := make([]fieldID, 0, len(fields))
	for _, field := range fields {
		out = append(out, compileField(field))
	}
	return out
}

func compileField(field string) fieldID {
	return detectioncompiler.ParseField(field)
}

func compileOp(op string) conditionOp {
	return detectioncompiler.ParseOperator(op)
}

func newEventView(ev *eventv1.CanonicalEvent) eventView {
	view := eventView{ev: ev}
	if ev == nil {
		return view
	}
	view.eventID = ev.GetId()
	view.behavior = eventBehavior(ev)
	view.lineageID = ev.GetLineageId()
	view.parentStableID = ev.GetParentStableId()
	view.containerID = ev.GetContainerId()
	view.cgroup = ev.GetCgroup()
	view.occurredAtNs = ev.GetOccurredAtNs()
	view.monoNs = ev.GetMonoNs()
	if proc := ev.GetSubjectProc(); proc != nil {
		view.processStableID = proc.GetStableId()
		view.processBinary = proc.GetBinary()
		view.processBinaryName = filepath.Base(proc.GetBinary())
		view.processArgv = strings.Join(proc.GetArgv(), " ")
		if filepath.Base(proc.GetBinary()) == "sudo" && proc.GetArgvBoundariesTrusted() {
			view.processSudoCommand = sudoCommand(proc.GetArgv())
		}
		view.processUID = strconv.FormatUint(uint64(proc.GetUid()), 10)
		if proc.GetPid() != 0 {
			view.processPID = strconv.FormatUint(uint64(proc.GetPid()), 10)
		}
	}
	if obj := ev.GetObject(); obj != nil {
		view.filePath = obj.GetFilePath()
		view.socket = obj.GetSocketAddr()
		if addr, port, ok := strings.Cut(view.socket, ":"); ok {
			view.socketAddr = addr
			view.socketPort = port
		} else {
			view.socketAddr = view.socket
		}
	}
	if scope := ev.GetScope(); scope != nil {
		view.scopeType = scope.GetType()
		view.scopeSelector = scope.GetSelector()
	}
	return view
}

func (v eventView) field(field fieldID) string {
	switch field {
	case fieldEventID:
		return v.eventID
	case fieldBehavior:
		return v.behavior
	case fieldLineageID:
		return v.lineageID
	case fieldProcessStableID:
		return v.processStableID
	case fieldProcessBinary:
		return v.processBinary
	case fieldProcessBinaryName:
		return v.processBinaryName
	case fieldProcessArgv:
		return v.processArgv
	case fieldProcessSudoCommand:
		return v.processSudoCommand
	case fieldProcessUID:
		return v.processUID
	case fieldProcessPID:
		return v.processPID
	case fieldParentStableID:
		return v.parentStableID
	case fieldFilePath:
		return v.filePath
	case fieldSocketAddr:
		return v.socketAddr
	case fieldSocketPort:
		return v.socketPort
	case fieldSocket:
		return v.socket
	case fieldScopeType:
		return v.scopeType
	case fieldScopeSelector:
		return v.scopeSelector
	case fieldContainerID:
		return v.containerID
	case fieldCgroup:
		return v.cgroup
	default:
		return ""
	}
}

func (v eventView) eventTime() uint64 {
	if v.occurredAtNs != 0 {
		return v.occurredAtNs
	}
	return v.monoNs
}

func (e *Engine) matchCompiledStep(view eventView, step compiledStep, st *cepGroupState) bool {
	if step.behavior != "" && view.behavior != step.behavior {
		return false
	}
	return e.matchCompiledConditions(view, step.conditions, st) && e.matchCompiledConditionNode(view, step.conditionGroup, st)
}

func (e *Engine) matchCompiledConditions(view eventView, conditions []compiledCondition, st *cepGroupState) bool {
	for _, cond := range conditions {
		if !e.matchCompiledCondition(view, cond, st) {
			return false
		}
	}
	return true
}

func (e *Engine) matchCompiledCondition(view eventView, cond compiledCondition, st *cepGroupState) bool {
	e.metrics.ConditionsEvaluated++
	e.metrics.FieldReads++
	return e.recordConditionResult(compiledConditionMatches(view, cond, st))
}

func compiledConditionMatches(view eventView, cond compiledCondition, st *cepGroupState) bool {
	actual := view.field(cond.field)
	switch cond.op {
	case opEq, opIn:
		return cond.matcher != nil && cond.matcher.Match(actual)
	case opNeq, opNotIn:
		return cond.matcher == nil || !cond.matcher.Match(actual)
	case opContains, opPrefix, opSuffix:
		return cond.matcher != nil && cond.matcher.Match(actual)
	case opSameAs:
		if st == nil || cond.step == "" {
			return false
		}
		stepValues := st.Values[cond.step]
		if stepValues == nil {
			return false
		}
		return actual != "" && actual == stepValues[fieldName(cond.stepField)]
	case opExists:
		return actual != ""
	case opGT, opGTE, opLT, opLTE:
		return compareNumber(actual, firstValue(cond.values), opString(cond.op))
	default:
		return false
	}
}

func (e *Engine) compiledSequenceGroupKey(view eventView, fields []fieldID) string {
	if len(fields) == 0 {
		fields = []fieldID{fieldLineageID}
	}
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		e.metrics.FieldReads++
		parts = append(parts, fieldName(field)+"="+view.field(field))
	}
	return strings.Join(parts, "|")
}

func eventFieldMapFromView(view eventView, fields []fieldID) map[string]string {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(fields))
	for _, field := range fields {
		out[fieldName(field)] = view.field(field)
	}
	return out
}

func fieldName(field fieldID) string {
	switch field {
	case fieldEventID:
		return "event.id"
	case fieldBehavior:
		return "event.behavior"
	case fieldLineageID:
		return "lineage_id"
	case fieldProcessStableID:
		return "process.stable_id"
	case fieldProcessBinary:
		return "process.binary"
	case fieldProcessBinaryName:
		return "process.binary_name"
	case fieldProcessArgv:
		return "process.argv"
	case fieldProcessSudoCommand:
		return "process.sudo_command"
	case fieldProcessUID:
		return "process.uid"
	case fieldProcessPID:
		return "process.pid"
	case fieldParentStableID:
		return "parent.stable_id"
	case fieldFilePath:
		return "file.path"
	case fieldSocketAddr:
		return "socket.addr"
	case fieldSocketPort:
		return "socket.port"
	case fieldSocket:
		return "socket"
	case fieldScopeType:
		return "scope.type"
	case fieldScopeSelector:
		return "scope.selector"
	case fieldContainerID:
		return "container.id"
	case fieldCgroup:
		return "cgroup"
	default:
		return ""
	}
}

func opString(op conditionOp) string {
	switch op {
	case opGT:
		return "gt"
	case opGTE:
		return "gte"
	case opLT:
		return "lt"
	case opLTE:
		return "lte"
	default:
		return ""
	}
}
