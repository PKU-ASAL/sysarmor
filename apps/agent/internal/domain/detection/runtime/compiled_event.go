package runtime

import (
	"path/filepath"
	"strconv"
	"strings"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func newEventView(ev domainevent.Event) eventView {
	view := eventView{ev: ev}
	view.eventID = ev.ID
	view.behavior = strings.ToLower(strings.TrimSpace(ev.Behavior))
	view.lineageID = ev.LineageID
	view.parentStableID = ev.ParentStableID
	view.containerID = ev.ContainerID
	view.cgroup = ev.Cgroup
	view.occurredAtNs = ev.OccurredAtNS
	view.monoNs = ev.MonoNS
	view.processStableID = ev.Subject.StableID
	view.processBinary = ev.Subject.Binary
	view.processBinaryName = filepath.Base(ev.Subject.Binary)
	view.processArgv = strings.Join(ev.Subject.Argv, " ")
	if filepath.Base(ev.Subject.Binary) == "sudo" && ev.Subject.ArgvBoundariesTrusted {
		view.processSudoCommand = sudoCommand(ev.Subject.Argv)
	}
	view.processUID = strconv.FormatUint(uint64(ev.Subject.UID), 10)
	if ev.Subject.PID != 0 {
		view.processPID = strconv.FormatUint(uint64(ev.Subject.PID), 10)
	}
	view.filePath = ev.Object.FilePath
	view.socket = ev.Object.SocketAddress
	if addr, port, ok := strings.Cut(view.socket, ":"); ok {
		view.socketAddr = addr
		view.socketPort = port
	} else {
		view.socketAddr = view.socket
	}
	view.scopeType = ev.Scope.Type
	view.scopeSelector = ev.Scope.Selector
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
