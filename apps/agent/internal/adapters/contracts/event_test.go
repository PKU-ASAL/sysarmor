package contracts

import (
	"testing"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestCanonicalEventMapsDomainProvenance(t *testing.T) {
	value := domainevent.Event{
		ID: "event-a", Sequence: 7, AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a",
		Behavior: "network.connect", OccurredAtNS: 42, ContainerID: "container-a", Cgroup: "cg-a",
		Subject: domainevent.Process{StableID: "process-a", PID: 10, Binary: "/bin/sh", Argv: []string{"sh", "-c"}, ArgvBoundariesTrusted: true},
		Object:  domainevent.Object{Kind: "socket", SocketAddress: "10.0.0.1:443"},
		Scope:   domainevent.RuntimeScope{Type: "container", Selector: "container-a"}, Labels: map[string]string{"env": "test"},
	}

	wire := CanonicalEvent(value)

	if wire.GetId() != value.ID || wire.GetSubjectProc().GetStableId() != "process-a" || !wire.GetSubjectProc().GetArgvBoundariesTrusted() {
		t.Fatalf("canonical event = %+v", wire)
	}
	if wire.GetObject().GetSocketAddr() != "10.0.0.1:443" || wire.GetScope().GetSelector() != "container-a" || wire.GetLabels()["env"] != "test" {
		t.Fatalf("canonical provenance = %+v", wire)
	}
}
