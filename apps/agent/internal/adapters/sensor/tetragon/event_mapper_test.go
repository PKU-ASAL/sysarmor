package tetragon

import (
	"fmt"
	"sync"
	"testing"

	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
)

func TestEventNormalizerInheritsSensorParentLineage(t *testing.T) {
	normalizer := NewEventNormalizer("agent-a", "host-a", EventNormalizerOptions{TenantID: "tenant-a"})
	parent := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		Behavior: " PROCESS.EXEC ", Proc: &sensorv1.RawProcess{Pid: 100, SensorExecId: "exec-parent", Binary: "/usr/bin/java"},
	})
	child := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		Behavior: "process.exec", Proc: &sensorv1.RawProcess{Pid: 101, Ppid: 100, SensorExecId: "exec-child", SensorParentExecId: "exec-parent", Binary: "/bin/bash"},
	})

	if parent.LineageID == "" || child.LineageID != parent.LineageID {
		t.Fatalf("parent lineage=%q child lineage=%q", parent.LineageID, child.LineageID)
	}
	if child.ParentStableID != parent.Subject.StableID || child.Behavior != "process.exec" {
		t.Fatalf("child = %+v", child)
	}
}

func TestEventNormalizerUsesSensorExecIdentityForParentage(t *testing.T) {
	normalizer := NewEventNormalizer("agent-a", "host-a", EventNormalizerOptions{})
	root := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		Behavior: "process.exec",
		Proc:     &sensorv1.RawProcess{Pid: 200, SensorExecId: "exec-root", Binary: "/bin/bash"},
	})
	helper := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		Behavior: "process.exec",
		Proc:     &sensorv1.RawProcess{Pid: 300, Ppid: 200, SensorExecId: "exec-helper", SensorParentExecId: "exec-root", Binary: "/var/lib/app/plugins/helper"},
	})
	bashAfterExec := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		Behavior: "process.exec",
		Proc:     &sensorv1.RawProcess{Pid: 300, Ppid: 300, SensorExecId: "exec-bash", SensorParentExecId: "exec-helper", Binary: "/bin/bash"},
	})

	if helper.LineageID != root.LineageID {
		t.Fatalf("helper lineage=%q, want root lineage %q", helper.LineageID, root.LineageID)
	}
	if bashAfterExec.ParentStableID != helper.Subject.StableID {
		t.Fatalf("bash parent stable ID=%q, want helper stable ID %q", bashAfterExec.ParentStableID, helper.Subject.StableID)
	}
	if bashAfterExec.Subject.StableID == helper.Subject.StableID {
		t.Fatal("same PID with different sensor exec ID should have a different stable ID")
	}
}

func TestEventNormalizerKeepsConcurrentIDAndSequenceConsistent(t *testing.T) {
	normalizer := NewEventNormalizer("agent-a", "host-a", EventNormalizerOptions{})
	const count = 1000
	events := make(chan struct {
		id       string
		sequence uint64
	}, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(pid uint32) {
			defer wait.Done()
			event := normalizer.NormalizeDomain(&sensorv1.SensorEvent{Proc: &sensorv1.RawProcess{Pid: pid}})
			events <- struct {
				id       string
				sequence uint64
			}{event.ID, event.Sequence}
		}(uint32(index + 1))
	}
	wait.Wait()
	close(events)
	for event := range events {
		want := fmt.Sprintf("agent-a-%020d", event.sequence)
		if event.id != want {
			t.Fatalf("event ID=%q sequence=%d, want %q", event.id, event.sequence, want)
		}
	}
}

func TestEventNormalizerPreservesIdentityScopeAndObject(t *testing.T) {
	normalizer := NewEventNormalizer("agent-a", "host-a", EventNormalizerOptions{
		TenantID: "tenant-a", ScopeType: "container", ScopeSelector: "container-a", Labels: map[string]string{"env": "test"}, InitialSequence: 41,
	})
	event := normalizer.NormalizeDomain(&sensorv1.SensorEvent{
		MonoNs: 100, Behavior: "network.connect", ContainerId: "container-a", RawRef: "raw-a",
		Proc:   &sensorv1.RawProcess{Pid: 10, Binary: "/bin/sh", Cgroup: "cg-a", ArgvBoundariesTrusted: true},
		Object: &sensorv1.RawObject{Dst: "10.0.0.1:443"},
	})

	if event.Sequence != 42 || event.AgentID != "agent-a" || event.TenantID != "tenant-a" || event.Scope.Selector != "container-a" {
		t.Fatalf("event identity = %+v", event)
	}
	if event.Object.Kind != "socket" || event.Object.SocketAddress != "10.0.0.1:443" || !event.Subject.ArgvBoundariesTrusted {
		t.Fatalf("event payload = %+v", event)
	}
}

func TestEventNormalizerSwitchesIdentityWithoutResettingSequence(t *testing.T) {
	normalizer := NewEventNormalizer("device-a", "host-a", EventNormalizerOptions{TenantID: "local"})
	first := normalizer.NormalizeDomain(&sensorv1.SensorEvent{Proc: &sensorv1.RawProcess{Pid: 1}})

	normalizer.SetIdentity("agent-a", "host-a", "tenant-a")
	second := normalizer.NormalizeDomain(&sensorv1.SensorEvent{Proc: &sensorv1.RawProcess{Pid: 2}})

	if second.AgentID != "agent-a" || second.HostID != "host-a" || second.TenantID != "tenant-a" {
		t.Fatalf("managed identity not applied: %+v", second)
	}
	if second.Sequence != first.Sequence+1 {
		t.Fatalf("sequence reset across identity switch: first=%d second=%d", first.Sequence, second.Sequence)
	}
}
