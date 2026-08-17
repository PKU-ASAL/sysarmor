package process

import (
	"slices"
	"testing"
	"time"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

func TestProfilesResolvePreservesParentLineageAcrossPIDReuse(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 16, MaxFiles: 4, MaxNetworks: 4, MaxEventRefs: 4})
	if err != nil {
		t.Fatal(err)
	}
	parent := profiles.Resolve(IdentityObservation{
		HostID:  "host-a",
		Process: domainevent.Process{PID: 100, SensorExecID: "exec-parent", Binary: "/usr/sbin/sshd"},
	})
	child := profiles.Resolve(IdentityObservation{
		HostID:             "host-a",
		ParentSensorExecID: "exec-parent",
		Process:            domainevent.Process{PID: 200, PPID: 100, SensorExecID: "exec-child", Binary: "/bin/bash"},
	})
	reused := profiles.Resolve(IdentityObservation{
		HostID:             "host-a",
		ParentSensorExecID: "exec-child",
		Process:            domainevent.Process{PID: 200, PPID: 200, SensorExecID: "exec-reused", Binary: "/usr/bin/curl"},
	})

	if parent.Process.StableID == "" || parent.Process.LineageID != parent.Process.StableID {
		t.Fatalf("parent identity = %+v", parent)
	}
	if child.ParentStableID != parent.Process.StableID || child.Process.LineageID != parent.Process.LineageID {
		t.Fatalf("child identity = %+v, parent = %+v", child, parent)
	}
	if reused.Process.StableID == child.Process.StableID {
		t.Fatal("same PID with a new sensor exec ID reused the previous stable identity")
	}
	if reused.ParentStableID != child.Process.StableID || reused.Process.LineageID != child.Process.LineageID {
		t.Fatalf("reused identity = %+v, child = %+v", reused, child)
	}
	if got, ok := profiles.Snapshot(child.Process.StableID); !ok || got.Binary != "/bin/bash" {
		t.Fatalf("old profile was lost after PID reuse: snapshot=%+v ok=%v", got, ok)
	}
}

func TestProfilesExitCompactsThenExpiresProfile(t *testing.T) {
	profiles, err := NewProfiles(Limits{
		MaxProfiles: 16, MaxFiles: 2, MaxNetworks: 2, MaxEventRefs: 2,
		ExitGrace: 10 * time.Nanosecond, RetainedTTL: 20 * time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 100, SensorExecID: "exec-a", Binary: "/bin/bash", Argv: []string{"bash", "-c", "curl example.test"}},
	})
	profiles.Observe(domainevent.Event{
		ID: "event-1", OccurredAtNS: 10, Behavior: "file.read", SubjectPresent: true, Subject: identity.Process,
		Object: domainevent.Object{FilePath: "/etc/passwd"},
	})
	profiles.Observe(domainevent.Event{
		ID: "event-2", OccurredAtNS: 20, Behavior: domainevent.BehaviorProcessExit,
		SubjectPresent: true, Subject: identity.Process,
	})
	exited, _ := profiles.Snapshot(identity.Process.StableID)
	if exited.State != StateExited || len(exited.Files) != 1 {
		t.Fatalf("exit snapshot = %+v", exited)
	}

	profiles.Sweep(30)
	retained, ok := profiles.Snapshot(identity.Process.StableID)
	if !ok || retained.State != StateRetained || len(retained.Files) != 0 || len(retained.EventRefs) != 0 {
		t.Fatalf("retained snapshot = %+v ok=%v", retained, ok)
	}
	metrics := profiles.Metrics()
	if metrics.Retained != 1 || metrics.Compactions != 1 {
		t.Fatalf("metrics after compaction = %+v", metrics)
	}

	profiles.Sweep(50)
	if _, ok := profiles.Snapshot(identity.Process.StableID); ok {
		t.Fatal("retained profile was not expired")
	}
	metrics = profiles.Metrics()
	if metrics.Expired != 1 || metrics.Retained != 0 {
		t.Fatalf("metrics after expiry = %+v", metrics)
	}
}

func TestProfilesObserveBuildsBoundedImmutableBehaviorSnapshot(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 16, MaxFiles: 2, MaxNetworks: 1, MaxEventRefs: 2})
	if err != nil {
		t.Fatal(err)
	}
	identity := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 100, SensorExecID: "exec-a", Binary: "/bin/bash", Argv: []string{"bash", "-c", "curl example.test"}},
	})
	for _, input := range []struct{ id, behavior, file, network string }{
		{"event-1", "file.read", "/usr/lib/libc.so", ""},
		{"event-2", "file.read", "/usr/lib/libc.so", ""},
		{"event-3", "file.write", "/tmp/payload", ""},
		{"event-4", "file.chmod", "/tmp/runner", ""},
		{"event-5", "network.connect", "", "10.0.0.9:443"},
	} {
		profiles.Observe(domainevent.Event{
			ID: input.id, Behavior: input.behavior, SubjectPresent: true, Subject: identity.Process,
			Object: domainevent.Object{FilePath: input.file, SocketAddress: input.network},
		})
	}

	snapshot, ok := profiles.Snapshot(identity.Process.StableID)
	if !ok {
		t.Fatal("profile snapshot not found")
	}
	if !slices.Equal(snapshot.Files, []string{"/tmp/payload", "/tmp/runner"}) {
		t.Fatalf("files = %v", snapshot.Files)
	}
	if !slices.Equal(snapshot.Networks, []string{"10.0.0.9:443"}) {
		t.Fatalf("networks = %v", snapshot.Networks)
	}
	if !slices.Equal(snapshot.EventRefs, []string{"event-4", "event-5"}) {
		t.Fatalf("event refs = %v", snapshot.EventRefs)
	}
	if snapshot.BehaviorCounts["file.read"] != 2 || snapshot.Revision != 5 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !slices.Equal(snapshot.Argv, []string{"bash", "-c", "curl example.test"}) {
		t.Fatalf("argv = %v", snapshot.Argv)
	}

	snapshot.Files[0] = "mutated"
	snapshot.Argv[0] = "mutated"
	snapshot.BehaviorCounts["file.read"] = 100
	again, _ := profiles.Snapshot(identity.Process.StableID)
	if again.Files[0] == "mutated" || again.Argv[0] == "mutated" || again.BehaviorCounts["file.read"] != 2 {
		t.Fatalf("snapshot mutated canonical profile: %+v", again)
	}
	metrics := profiles.Metrics()
	if metrics.FileEvictions != 1 || metrics.EventRefEvictions != 3 {
		t.Fatalf("bounded metrics = %+v", metrics)
	}
}

func TestProfilesCapacityPrefersExitedProfile(t *testing.T) {
	profiles, err := NewProfiles(Limits{
		MaxProfiles: 2, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1,
		ExitGrace: time.Minute, RetainedTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 1, SensorExecID: "exec-1", Binary: "/bin/first"},
	})
	second := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 2, SensorExecID: "exec-2", Binary: "/bin/second"},
	})
	profiles.Observe(domainevent.Event{
		ID: "exit-1", OccurredAtNS: 10, Behavior: domainevent.BehaviorProcessExit,
		SubjectPresent: true, Subject: first.Process,
	})
	third := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 3, SensorExecID: "exec-3", Binary: "/bin/third"},
	})

	if _, ok := profiles.Snapshot(first.Process.StableID); ok {
		t.Fatal("exited profile survived capacity eviction")
	}
	for _, stableID := range []string{second.Process.StableID, third.Process.StableID} {
		if _, ok := profiles.Snapshot(stableID); !ok {
			t.Fatalf("active profile %s was evicted", stableID)
		}
	}
	if metrics := profiles.Metrics(); metrics.Active != 2 || metrics.CapacityEvictions != 1 {
		t.Fatalf("capacity metrics = %+v", metrics)
	}
}

func TestProfilesObserveRunsLifecycleSweepAtConfiguredInterval(t *testing.T) {
	profiles, err := NewProfiles(Limits{
		MaxProfiles: 4, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1,
		ExitGrace: 5 * time.Nanosecond, RetainedTTL: time.Minute, SweepInterval: 10 * time.Nanosecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 1, SensorExecID: "exec-1"}})
	second := profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 2, SensorExecID: "exec-2"}})
	profiles.Observe(domainevent.Event{
		ID: "exit", OccurredAtNS: 10, Behavior: domainevent.BehaviorProcessExit, SubjectPresent: true, Subject: first.Process,
	})
	profiles.Observe(domainevent.Event{
		ID: "tick", OccurredAtNS: 20, Behavior: domainevent.BehaviorProcessExec, SubjectPresent: true, Subject: second.Process,
	})

	snapshot, ok := profiles.Snapshot(first.Process.StableID)
	if !ok || snapshot.State != StateRetained {
		t.Fatalf("automatic sweep snapshot = %+v ok=%v", snapshot, ok)
	}
}

func TestProfilesObserveDoesNotAllocateSnapshotOnStableUpdate(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 4, MaxFiles: 2, MaxNetworks: 2, MaxEventRefs: 2})
	if err != nil {
		t.Fatal(err)
	}
	identity := profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 1, SensorExecID: "exec-1"}})
	event := domainevent.Event{
		ID: "event-a", Behavior: "file.read", SubjectPresent: true, Subject: identity.Process,
		Object: domainevent.Object{FilePath: "/usr/lib/libc.so"},
	}
	profiles.Observe(event)
	allocations := testing.AllocsPerRun(100, func() { profiles.Observe(event) })
	if allocations != 0 {
		t.Fatalf("stable Observe allocations = %.2f, want 0", allocations)
	}
}
