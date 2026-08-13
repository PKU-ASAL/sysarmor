package tetragon

import (
	"path/filepath"
	"strings"
	"sync/atomic"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
)

type EventIdentity struct {
	AgentID  string
	HostID   string
	TenantID string
}

type EventNormalizerOptions struct {
	TenantID        string
	ScopeType       string
	ScopeSelector   string
	Labels          map[string]string
	InitialSequence uint64
}

type EventNormalizer struct {
	identity atomic.Pointer[EventIdentity]
	scope    domainevent.RuntimeScope
	labels   map[string]string
	table    *domainevent.ProcessTable
	sequence atomic.Uint64
}

func NewEventNormalizer(agentID, hostID string, options EventNormalizerOptions) *EventNormalizer {
	if options.ScopeType == "" {
		options.ScopeType = "host"
	}
	normalizer := &EventNormalizer{
		scope:  domainevent.RuntimeScope{Type: options.ScopeType, Selector: options.ScopeSelector},
		labels: cleanLabels(options.Labels), table: domainevent.NewProcessTable(),
	}
	normalizer.sequence.Store(options.InitialSequence)
	normalizer.SetIdentity(agentID, hostID, options.TenantID)
	return normalizer
}

func (normalizer *EventNormalizer) SetIdentity(agentID, hostID, tenantID string) {
	normalizer.identity.Store(&EventIdentity{AgentID: agentID, HostID: hostID, TenantID: tenantID})
}

func (normalizer *EventNormalizer) NormalizeDomain(raw *sensorv1.SensorEvent) domainevent.Event {
	identity := normalizer.identity.Load()
	sequence := normalizer.sequence.Add(1)
	process, parentID, lineageID := normalizer.process(raw, identity.HostID)
	return domainevent.Event{
		ID: domainevent.EventID(identity.AgentID, sequence), Sequence: sequence,
		AgentID: identity.AgentID, HostID: identity.HostID, TenantID: identity.TenantID,
		MonoNS: raw.GetMonoNs(), OccurredAtNS: raw.GetMonoNs(), Behavior: domainevent.NormalizeBehavior(raw.GetBehavior()),
		Subject: process, Object: eventObject(raw), ParentStableID: parentID, LineageID: lineageID,
		RawRef: raw.GetRawRef(), Scope: normalizer.scope, ContainerID: raw.GetContainerId(), Cgroup: raw.GetProc().GetCgroup(),
		Labels: cloneLabels(normalizer.labels),
	}
}

func (normalizer *EventNormalizer) process(raw *sensorv1.SensorEvent, hostID string) (domainevent.Process, string, string) {
	value := raw.GetProc()
	stableID := domainevent.StableProcessID(hostID, value.GetPid(), value.GetStartTimeNs())
	if value.GetSensorExecId() != "" {
		stableID = domainevent.SensorProcessID(hostID, value.GetSensorExecId())
	}
	parent, found := normalizer.parent(value)
	lineageID, parentID := stableID, ""
	if found {
		parentID = parent.StableID
		if parent.LineageID != "" {
			lineageID = parent.LineageID
		}
	}
	process := domainevent.Process{
		StableID: stableID, SensorExecID: value.GetSensorExecId(), PID: value.GetPid(), PPID: value.GetPpid(),
		Binary: cleanBinary(value.GetBinary()), Argv: append([]string(nil), value.GetArgv()...), UID: value.GetUid(),
		StartTimeNS: value.GetStartTimeNs(), ArgvBoundariesTrusted: value.GetArgvBoundariesTrusted(), LineageID: lineageID,
	}
	normalizer.table.Upsert(process)
	return process, parentID, lineageID
}

func (normalizer *EventNormalizer) parent(process *sensorv1.RawProcess) (domainevent.Process, bool) {
	if process.GetSensorParentExecId() != "" {
		if parent, ok := normalizer.table.BySensorExecID(process.GetSensorParentExecId()); ok {
			return parent, true
		}
	}
	return normalizer.table.ByPID(process.GetPpid())
}

func eventObject(raw *sensorv1.SensorEvent) domainevent.Object {
	switch domainevent.NormalizeBehavior(raw.GetBehavior()) {
	case "network.connect":
		return domainevent.Object{Kind: "socket", SocketAddress: raw.GetObject().GetDst()}
	case "file.open", "file.read", "file.write", "file.chmod":
		return domainevent.Object{Kind: "file", FilePath: raw.GetObject().GetPath()}
	default:
		return domainevent.Object{Kind: "process"}
	}
}

func cleanBinary(value string) string {
	if strings.Contains(value, "/") {
		return filepath.Clean(value)
	}
	return value
}

func cleanLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		if key = strings.TrimSpace(key); key != "" {
			result[key] = value
		}
	}
	return result
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
