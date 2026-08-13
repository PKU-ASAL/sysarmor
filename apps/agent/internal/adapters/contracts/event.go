package contracts

import (
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
)

func CanonicalEvent(value domainevent.Event) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: value.ID, Seq: value.Sequence, AgentId: value.AgentID, HostId: value.HostID, TenantId: value.TenantID,
		MonoNs: value.MonoNS, OccurredAtNs: value.OccurredAtNS, Behavior: value.Behavior,
		SubjectProc: &eventv1.ProcessRef{
			StableId: value.Subject.StableID, Pid: value.Subject.PID, Binary: value.Subject.Binary,
			Argv: append([]string(nil), value.Subject.Argv...), Uid: value.Subject.UID,
			StartTimeNs: value.Subject.StartTimeNS, ArgvBoundariesTrusted: value.Subject.ArgvBoundariesTrusted,
		},
		Object: &eventv1.ObjectRef{
			Kind: value.Object.Kind, FilePath: value.Object.FilePath, SocketAddr: value.Object.SocketAddress,
			TargetProcStableId: value.Object.TargetProcessStableID,
		},
		ParentStableId: value.ParentStableID, LineageId: value.LineageID, RawRef: value.RawRef,
		Scope:       &eventv1.RuntimeScope{Type: value.Scope.Type, Selector: value.Scope.Selector},
		ContainerId: value.ContainerID, Cgroup: value.Cgroup, Namespace: value.Namespace, Pod: value.Pod,
		Labels: cloneEventLabels(value.Labels),
	}
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
