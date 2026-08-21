package provenance

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestFromEventNormalizesProvenanceDirection(t *testing.T) {
	tests := []struct {
		name, behavior, from, to, operation string
		parent, file, socket                string
	}{
		{name: "exec", behavior: "process.exec", parent: "parent", from: "process:parent", to: "process:child", operation: "exec"},
		{name: "read", behavior: "file.read", file: "/tmp/input", from: "file:/tmp/input", to: "process:child", operation: "read"},
		{name: "write", behavior: "file.write", file: "/tmp/output", from: "process:child", to: "file:/tmp/output", operation: "write"},
		{name: "connect", behavior: "network.connect", socket: "10.0.0.1:443", from: "process:child", to: "socket:10.0.0.1:443", operation: "connect"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := domaintelemetry.Event{
				ID: "event-1", Behavior: test.behavior, ParentStableID: test.parent,
				SubjectProcess: &domaintelemetry.ProcessRef{StableID: "child"},
				Object:         &domaintelemetry.ObjectRef{FilePath: test.file, SocketAddress: test.socket},
			}
			edge, ok := FromEvent(event)
			if !ok || edge.From != test.from || edge.To != test.to || edge.Operation != test.operation || len(edge.EventRefs) != 1 || edge.EventRefs[0] != "event-1" {
				t.Fatalf("edge = %+v ok=%v", edge, ok)
			}
		})
	}
}

func TestFromEventIgnoresLifecycleOnlyExit(t *testing.T) {
	_, ok := FromEvent(domaintelemetry.Event{
		ID: "exit-1", Behavior: "process.exit", SubjectProcess: &domaintelemetry.ProcessRef{StableID: "child"},
	})
	if ok {
		t.Fatal("process.exit produced a ProvenanceEdge")
	}
}

func TestFromEventMarksUnavailableParentAsIncompleteGap(t *testing.T) {
	edge, ok := FromEvent(domaintelemetry.Event{
		ID: "exec-1", Behavior: "process.exec", IdentityStatus: "unavailable",
		SubjectProcess: &domaintelemetry.ProcessRef{StableID: "child"},
	})
	if !ok || edge.From != "gap:parent:exec-1" || edge.To != "process:child" || !edge.Incomplete {
		t.Fatalf("edge = %+v ok=%v", edge, ok)
	}
}
