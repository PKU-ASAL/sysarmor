package contracts

import (
	"reflect"
	"testing"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
)

func TestCanonicalEventMapsDomainProvenance(t *testing.T) {
	value := domainevent.Event{
		ID: "event-a", Sequence: 7, AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a",
		Behavior: "network.connect", OccurredAtNS: 42, ContainerID: "container-a", Cgroup: "cg-a",
		Subject: domainevent.Process{StableID: "process-a", PID: 10, Binary: "/bin/sh", Argv: []string{"sh", "-c"}, ArgvBoundariesTrusted: true}, SubjectPresent: true,
		Object: domainevent.Object{Kind: "socket", SocketAddress: "10.0.0.1:443"},
		Scope:  domainevent.RuntimeScope{Type: "container", Selector: "container-a"}, Labels: map[string]string{"env": "test"},
	}

	wire := CanonicalEvent(value)

	if wire.GetId() != value.ID || wire.GetSubjectProc().GetStableId() != "process-a" || !wire.GetSubjectProc().GetArgvBoundariesTrusted() {
		t.Fatalf("canonical event = %+v", wire)
	}
	if wire.GetObject().GetSocketAddr() != "10.0.0.1:443" || wire.GetScope().GetSelector() != "container-a" || wire.GetLabels()["env"] != "test" {
		t.Fatalf("canonical provenance = %+v", wire)
	}
}

func TestDomainEventMapsCanonicalProvenance(t *testing.T) {
	wire := CanonicalEvent(domainevent.Event{
		ID: "event-a", Sequence: 7, AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a",
		MonoNS: 41, OccurredAtNS: 42, Behavior: "network.connect", ParentStableID: "parent-a", LineageID: "lineage-a",
		RawRef: "raw-a", ContainerID: "container-a", Cgroup: "cg-a", Namespace: "ns-a", Pod: "pod-a",
		Subject: domainevent.Process{StableID: "process-a", SensorExecID: "exec-a", PID: 10, PPID: 5, Binary: "/bin/sh", Argv: []string{"sh", "-c"}, UID: 1000, StartTimeNS: 40, ArgvBoundariesTrusted: true, LineageID: "lineage-a"}, SubjectPresent: true,
		Object: domainevent.Object{Kind: "socket", SocketAddress: "10.0.0.1:443", TargetProcessStableID: "target-a"},
		Scope:  domainevent.RuntimeScope{Type: "container", Selector: "container-a"}, Labels: map[string]string{"env": "test"},
	})

	got := DomainEvent(wire)
	want := domainevent.Event{
		ID: "event-a", Sequence: 7, AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a",
		MonoNS: 41, OccurredAtNS: 42, Behavior: "network.connect", ParentStableID: "parent-a", LineageID: "lineage-a",
		RawRef: "raw-a", ContainerID: "container-a", Cgroup: "cg-a", Namespace: "ns-a", Pod: "pod-a",
		Subject: domainevent.Process{StableID: "process-a", PID: 10, Binary: "/bin/sh", Argv: []string{"sh", "-c"}, UID: 1000, StartTimeNS: 40, ArgvBoundariesTrusted: true}, SubjectPresent: true,
		Object: domainevent.Object{Kind: "socket", SocketAddress: "10.0.0.1:443", TargetProcessStableID: "target-a"},
		Scope:  domainevent.RuntimeScope{Type: "container", Selector: "container-a"}, Labels: map[string]string{"env": "test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DomainEvent() = %+v, want %+v", got, want)
	}
	wire.SubjectProc.Argv[0] = "changed"
	wire.Labels["env"] = "changed"
	if got.Subject.Argv[0] != "sh" || got.Labels["env"] != "test" {
		t.Fatalf("domain event aliases wire input: %+v", got)
	}
}

func TestDomainEventMarksMissingSubject(t *testing.T) {
	got := DomainEvent(&eventv1.CanonicalEvent{Behavior: "file.read"})
	if got.SubjectPresent {
		t.Fatalf("SubjectPresent = true, want false: %+v", got)
	}
}

func TestCanonicalEventPreservesMissingSubject(t *testing.T) {
	wire := CanonicalEvent(domainevent.Event{Behavior: "file.read", Object: domainevent.Object{FilePath: "/tmp/x"}})
	if wire.GetSubjectProc() != nil {
		t.Fatalf("SubjectProc = %+v, want nil", wire.GetSubjectProc())
	}
	if got := DomainEvent(wire); got.SubjectPresent {
		t.Fatalf("round-trip SubjectPresent = true, want false: %+v", got)
	}
}
