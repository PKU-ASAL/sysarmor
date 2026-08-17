package contracts

import (
	"fmt"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
)

func EventToDomain(value *eventv1.CanonicalEvent) (domaintelemetry.Event, error) {
	if value == nil {
		return domaintelemetry.Event{}, fmt.Errorf("canonical event is required")
	}
	return domaintelemetry.Event{
		ID: value.GetId(), Sequence: value.GetSeq(), AgentID: value.GetAgentId(), HostID: value.GetHostId(),
		MonotonicNS: value.GetMonoNs(), SubjectProcess: processToDomain(value.SubjectProc), Object: objectToDomain(value.Object),
		ParentStableID: value.GetParentStableId(), LineageID: value.GetLineageId(), IdentityStatus: value.GetIdentityStatus(), RawRef: value.GetRawRef(),
		TenantID: value.GetTenantId(), Scope: scopeToDomain(value.Scope), ContainerID: value.GetContainerId(),
		Cgroup: value.GetCgroup(), Namespace: value.GetNamespace(), Pod: value.GetPod(), OccurredAtNS: value.GetOccurredAtNs(),
		Behavior: value.GetBehavior(), Labels: cloneLabels(value.GetLabels()),
	}, nil
}

func EventFromDomain(value domaintelemetry.Event) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{
		Id: value.ID, Seq: value.Sequence, AgentId: value.AgentID, HostId: value.HostID,
		MonoNs: value.MonotonicNS, SubjectProc: processFromDomain(value.SubjectProcess), Object: objectFromDomain(value.Object),
		ParentStableId: value.ParentStableID, LineageId: value.LineageID, IdentityStatus: value.IdentityStatus, RawRef: value.RawRef,
		TenantId: value.TenantID, Scope: scopeFromDomain(value.Scope), ContainerId: value.ContainerID,
		Cgroup: value.Cgroup, Namespace: value.Namespace, Pod: value.Pod, OccurredAtNs: value.OccurredAtNS,
		Behavior: value.Behavior, Labels: cloneLabels(value.Labels),
	}
}

func processToDomain(value *eventv1.ProcessRef) *domaintelemetry.ProcessRef {
	if value == nil {
		return nil
	}
	return &domaintelemetry.ProcessRef{
		StableID: value.GetStableId(), PID: value.GetPid(), Binary: value.GetBinary(), Argv: append([]string(nil), value.GetArgv()...),
		UID: value.GetUid(), StartTimeNS: value.GetStartTimeNs(), ArgvBoundariesTrusted: value.GetArgvBoundariesTrusted(),
	}
}

func processFromDomain(value *domaintelemetry.ProcessRef) *eventv1.ProcessRef {
	if value == nil {
		return nil
	}
	return &eventv1.ProcessRef{
		StableId: value.StableID, Pid: value.PID, Binary: value.Binary, Argv: append([]string(nil), value.Argv...),
		Uid: value.UID, StartTimeNs: value.StartTimeNS, ArgvBoundariesTrusted: value.ArgvBoundariesTrusted,
	}
}

func objectToDomain(value *eventv1.ObjectRef) *domaintelemetry.ObjectRef {
	if value == nil {
		return nil
	}
	return &domaintelemetry.ObjectRef{Kind: value.GetKind(), FilePath: value.GetFilePath(), SocketAddress: value.GetSocketAddr(), TargetProcStableID: value.GetTargetProcStableId()}
}

func objectFromDomain(value *domaintelemetry.ObjectRef) *eventv1.ObjectRef {
	if value == nil {
		return nil
	}
	return &eventv1.ObjectRef{Kind: value.Kind, FilePath: value.FilePath, SocketAddr: value.SocketAddress, TargetProcStableId: value.TargetProcStableID}
}

func scopeToDomain(value *eventv1.RuntimeScope) *domaintelemetry.RuntimeScope {
	if value == nil {
		return nil
	}
	return &domaintelemetry.RuntimeScope{Type: value.GetType(), Selector: value.GetSelector()}
}

func scopeFromDomain(value *domaintelemetry.RuntimeScope) *eventv1.RuntimeScope {
	if value == nil {
		return nil
	}
	return &eventv1.RuntimeScope{Type: value.Type, Selector: value.Selector}
}
