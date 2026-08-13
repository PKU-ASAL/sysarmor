package contracts

import (
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
)

func CanonicalEvent(value domainevent.Event) *eventv1.CanonicalEvent {
	result := &eventv1.CanonicalEvent{
		Id: value.ID, Seq: value.Sequence, AgentId: value.AgentID, HostId: value.HostID, TenantId: value.TenantID,
		MonoNs: value.MonoNS, OccurredAtNs: value.OccurredAtNS, Behavior: value.Behavior,
		Object: &eventv1.ObjectRef{
			Kind: value.Object.Kind, FilePath: value.Object.FilePath, SocketAddr: value.Object.SocketAddress,
			TargetProcStableId: value.Object.TargetProcessStableID,
		},
		ParentStableId: value.ParentStableID, LineageId: value.LineageID, RawRef: value.RawRef,
		Scope:       &eventv1.RuntimeScope{Type: value.Scope.Type, Selector: value.Scope.Selector},
		ContainerId: value.ContainerID, Cgroup: value.Cgroup, Namespace: value.Namespace, Pod: value.Pod,
		Labels: cloneEventLabels(value.Labels),
	}
	if value.SubjectPresent {
		result.SubjectProc = &eventv1.ProcessRef{
			StableId: value.Subject.StableID, Pid: value.Subject.PID, Binary: value.Subject.Binary,
			Argv: append([]string(nil), value.Subject.Argv...), Uid: value.Subject.UID,
			StartTimeNs: value.Subject.StartTimeNS, ArgvBoundariesTrusted: value.Subject.ArgvBoundariesTrusted,
		}
	}
	return result
}

func DomainEvent(value *eventv1.CanonicalEvent) domainevent.Event {
	if value == nil {
		return domainevent.Event{}
	}
	result := domainevent.Event{
		ID: value.GetId(), Sequence: value.GetSeq(), AgentID: value.GetAgentId(), HostID: value.GetHostId(), TenantID: value.GetTenantId(),
		MonoNS: value.GetMonoNs(), OccurredAtNS: value.GetOccurredAtNs(), Behavior: value.GetBehavior(),
		ParentStableID: value.GetParentStableId(), LineageID: value.GetLineageId(), RawRef: value.GetRawRef(),
		ContainerID: value.GetContainerId(), Cgroup: value.GetCgroup(), Namespace: value.GetNamespace(), Pod: value.GetPod(),
		Labels: cloneEventLabels(value.GetLabels()),
	}
	if process := value.GetSubjectProc(); process != nil {
		result.SubjectPresent = true
		result.Subject = domainevent.Process{
			StableID: process.GetStableId(), PID: process.GetPid(), Binary: process.GetBinary(),
			Argv: append([]string(nil), process.GetArgv()...), UID: process.GetUid(),
			StartTimeNS: process.GetStartTimeNs(), ArgvBoundariesTrusted: process.GetArgvBoundariesTrusted(),
		}
	}
	if object := value.GetObject(); object != nil {
		result.Object = domainevent.Object{
			Kind: object.GetKind(), FilePath: object.GetFilePath(), SocketAddress: object.GetSocketAddr(),
			TargetProcessStableID: object.GetTargetProcStableId(),
		}
	}
	if scope := value.GetScope(); scope != nil {
		result.Scope = domainevent.RuntimeScope{Type: scope.GetType(), Selector: scope.GetSelector()}
	}
	return result
}

func cloneEventLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
