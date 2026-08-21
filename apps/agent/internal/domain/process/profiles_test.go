package process

import (
	"fmt"
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

func TestProfilesObserveChangesClassifiesLearningCheckpoints(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 8, MaxFiles: 4, MaxNetworks: 4, MaxEventRefs: 8})
	if err != nil {
		t.Fatal(err)
	}
	identity := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 100, SensorExecID: "exec-a", Binary: "/bin/bash"},
	})

	checks := []struct {
		name               string
		event              domainevent.Event
		lifecycle, feature bool
		needsScore         bool
	}{
		{name: "exec", event: profileEvent(identity.Process, "exec-1", domainevent.BehaviorProcessExec), lifecycle: true, feature: true, needsScore: true},
		{name: "fork", event: profileEvent(identity.Process, "fork-1", domainevent.BehaviorProcessFork), lifecycle: true},
		{name: "new file", event: fileEvent(identity.Process, "file-1", "/tmp/payload"), feature: true, needsScore: true},
		{name: "duplicate file", event: fileEvent(identity.Process, "file-2", "/tmp/payload")},
		{name: "exit", event: profileEvent(identity.Process, "exit-1", domainevent.BehaviorProcessExit), lifecycle: true},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			observation, ok := profiles.ObserveChanges(check.event)
			if !ok {
				t.Fatal("ObserveChanges() did not find profile")
			}
			if observation.LifecycleChanged != check.lifecycle || observation.FeatureChanged != check.feature || observation.ScoreRequired != check.needsScore {
				t.Fatalf("observation = %+v", observation)
			}
		})
		if check.needsScore {
			profiles.MarkScored(identity.Process.StableID, observationFeatureRevision(t, profiles, identity.Process.StableID))
		}
	}
}

func TestProfilesMetricsTrackLearningSemanticScheduling(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 4, MaxFiles: 2, MaxNetworks: 2, MaxEventRefs: 8})
	if err != nil {
		t.Fatal(err)
	}
	resolved := profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 7, SensorExecID: "exec-a"}})
	observe := func(id, behavior, file string) Observation {
		t.Helper()
		observation, ok := profiles.ObserveChanges(domainevent.Event{
			ID: id, Behavior: behavior, SubjectPresent: true, Subject: resolved.Process,
			Object: domainevent.Object{FilePath: file},
		})
		if !ok {
			t.Fatalf("observation %s was not recorded", id)
		}
		return observation
	}

	exec := observe("event-exec", domainevent.BehaviorProcessExec, "")
	profiles.MarkScored(exec.StableID, exec.FeatureRevision)
	observe("event-fork", domainevent.BehaviorProcessFork, "")
	file := observe("event-file", domainevent.BehaviorFileOpen, "/tmp/a")
	profiles.MarkScored(file.StableID, file.FeatureRevision)
	observe("event-exit", domainevent.BehaviorProcessExit, "")

	metrics := profiles.Metrics()
	if metrics.ProfileObservations != 4 || metrics.FeatureUpdates != 2 || metrics.LearningScoreCalls != 2 ||
		metrics.LifecycleOnlyObservations != 2 || metrics.SuppressedCheckpoints != 2 {
		t.Fatalf("scheduling metrics = %+v", metrics)
	}
}

func TestProfilesExitRequiresScoreForUnscoredFeatureChanges(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 4, MaxFiles: 2, MaxNetworks: 2, MaxEventRefs: 4})
	if err != nil {
		t.Fatal(err)
	}
	identity := profiles.Resolve(IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 8, SensorExecID: "exec-a"},
	})
	profiles.Observe(fileEvent(identity.Process, "file-1", "/tmp/payload"))
	observation, ok := profiles.ObserveChanges(profileEvent(identity.Process, "exit-1", domainevent.BehaviorProcessExit))
	if !ok || !observation.ScoreRequired || !observation.LifecycleChanged || observation.FeatureChanged {
		t.Fatalf("exit observation = %+v ok=%v", observation, ok)
	}
	profiles.MarkScored(identity.Process.StableID, observation.FeatureRevision)
	observation, ok = profiles.ObserveChanges(profileEvent(identity.Process, "exit-2", domainevent.BehaviorProcessExit))
	if !ok || observation.ScoreRequired {
		t.Fatalf("repeated exit observation = %+v ok=%v", observation, ok)
	}
}

func observationFeatureRevision(t *testing.T, profiles *Profiles, stableID string) uint64 {
	t.Helper()
	snapshot, ok := profiles.Snapshot(stableID)
	if !ok {
		t.Fatalf("profile %q not found", stableID)
	}
	return snapshot.FeatureRevision
}

func profileEvent(process domainevent.Process, id, behavior string) domainevent.Event {
	return domainevent.Event{ID: id, Behavior: behavior, SubjectPresent: true, Subject: process}
}

func fileEvent(process domainevent.Process, id, path string) domainevent.Event {
	event := profileEvent(process, id, "file.write")
	event.Object = domainevent.Object{Kind: "file", FilePath: path}
	return event
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

func TestProfilesResolveUsesIdentityAnchorAfterParentCapacityEviction(t *testing.T) {
	profiles, err := NewProfiles(Limits{
		MaxProfiles: 1, MaxIdentityAnchors: 2, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1,
		RetainedTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := profiles.Resolve(IdentityObservation{
		HostID: "host-a", OccurredAtNS: 10,
		Process: domainevent.Process{PID: 10, SensorExecID: "exec-parent", Binary: "/usr/sbin/sshd"},
	})
	profiles.Resolve(IdentityObservation{
		HostID: "host-a", OccurredAtNS: 20,
		Process: domainevent.Process{PID: 20, SensorExecID: "exec-unrelated", Binary: "/bin/sleep"},
	})
	child := profiles.Resolve(IdentityObservation{
		HostID: "host-a", OccurredAtNS: 30, ParentSensorExecID: "exec-parent",
		Process: domainevent.Process{PID: 30, PPID: 10, SensorExecID: "exec-child", Binary: "/bin/bash"},
	})

	if child.ParentStableID != parent.Process.StableID || child.Process.LineageID != parent.Process.LineageID {
		t.Fatalf("child=%+v parent=%+v", child, parent)
	}
	if child.IdentityStatus != IdentityResolved {
		t.Fatalf("identity status = %q", child.IdentityStatus)
	}
	if metrics := profiles.Metrics(); metrics.IdentityRetained == 0 {
		t.Fatalf("identity metrics = %+v", metrics)
	}
}

func TestProfilesIdentityAnchorsRemainBounded(t *testing.T) {
	profiles, err := NewProfiles(Limits{
		MaxProfiles: 1, MaxIdentityAnchors: 2, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1,
		RetainedTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := uint32(1); index <= 4; index++ {
		profiles.Resolve(IdentityObservation{
			HostID: "host-a", OccurredAtNS: uint64(index),
			Process: domainevent.Process{PID: index, SensorExecID: fmt.Sprintf("exec-%d", index)},
		})
	}
	metrics := profiles.Metrics()
	if metrics.IdentityRetained != 2 || metrics.IdentityEvictions != 1 || metrics.ActiveEvictions != 3 {
		t.Fatalf("identity metrics = %+v", metrics)
	}
}

func TestProfilesMarksMissingParentIdentityAsUnavailable(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 1, MaxIdentityAnchors: 1, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1})
	if err != nil {
		t.Fatal(err)
	}
	child := profiles.Resolve(IdentityObservation{
		HostID: "host-a", ParentSensorExecID: "missing-parent",
		Process: domainevent.Process{PID: 20, PPID: 10, SensorExecID: "exec-child"},
	})
	if child.IdentityStatus != IdentityUnavailable || child.ParentStableID != "" {
		t.Fatalf("child identity = %+v", child)
	}
	if metrics := profiles.Metrics(); metrics.IdentityGaps != 1 {
		t.Fatalf("identity metrics = %+v", metrics)
	}
}

func TestProfilesDoesNotFallbackToReusedPIDWhenParentSensorIdentityIsMissing(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 4, MaxIdentityAnchors: 4, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1})
	if err != nil {
		t.Fatal(err)
	}
	unrelated := profiles.Resolve(IdentityObservation{
		HostID:  "host-a",
		Process: domainevent.Process{PID: 10, SensorExecID: "exec-unrelated"},
	})
	child := profiles.Resolve(IdentityObservation{
		HostID: "host-a", ParentSensorExecID: "exec-missing-parent",
		Process: domainevent.Process{PID: 20, PPID: 10, SensorExecID: "exec-child"},
	})

	if child.IdentityStatus != IdentityUnavailable || child.ParentStableID != "" {
		t.Fatalf("child identity = %+v, unrelated = %+v", child, unrelated)
	}
}

func TestProfilesRestoresEvictedActiveIdentityFromOwnAnchor(t *testing.T) {
	profiles, err := NewProfiles(Limits{MaxProfiles: 1, MaxIdentityAnchors: 2, MaxFiles: 1, MaxNetworks: 1, MaxEventRefs: 1})
	if err != nil {
		t.Fatal(err)
	}
	parent := profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 1, SensorExecID: "parent"}})
	child := profiles.Resolve(IdentityObservation{
		HostID: "host-a", ParentSensorExecID: "parent",
		Process: domainevent.Process{PID: 2, PPID: 1, SensorExecID: "child"},
	})
	profiles.Resolve(IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 3, SensorExecID: "other"}})
	restored := profiles.Resolve(IdentityObservation{
		HostID: "host-a", ParentSensorExecID: "parent",
		Process: domainevent.Process{PID: 2, PPID: 1, SensorExecID: "child"},
	})
	if restored.ParentStableID != parent.Process.StableID || restored.Process.LineageID != child.Process.LineageID || restored.IdentityStatus != IdentityResolved {
		t.Fatalf("restored=%+v child=%+v parent=%+v", restored, child, parent)
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
