package pipeline

import (
	"sync"
	"testing"
	"time"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

func TestProcessMergesPolicyLabelsBeforeDetection(t *testing.T) {
	detector := &detectorFake{signals: []*domaindetection.Signal{{ID: "signal-a"}}}
	profiles := testProfiles(t)
	identity := profiles.Resolve(domainprocess.IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 7, StartTimeNS: 1}})
	learning := &profileDetectorFake{signals: []*domaindetection.Signal{{ID: "model-a"}}}
	service := New(detector, learning, profiles)
	original := domainevent.Event{ID: "event-a", Subject: identity.Process, Behavior: "process.exec", Labels: map[string]string{"scenario": "test", "policy_id": "old"}}

	result, err := service.Process(original, map[string]string{"policy_id": "policy-a", "policy_version": "7"})
	if err != nil {
		t.Fatal(err)
	}
	if detector.event.Labels["policy_id"] != "policy-a" || detector.event.Labels["scenario"] != "test" {
		t.Fatalf("detector labels = %+v", detector.event.Labels)
	}
	if result.Event.Labels["policy_version"] != "7" || len(result.Signals) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if learning.snapshot.StableID != identity.Process.StableID || learning.snapshot.Revision != 1 {
		t.Fatalf("learning snapshot = %+v", learning.snapshot)
	}
	if learning.snapshot.Labels["policy_id"] != "policy-a" || learning.snapshot.Labels["scenario"] != "test" {
		t.Fatalf("learning labels = %+v", learning.snapshot.Labels)
	}
	if original.Labels["policy_id"] != "old" || len(original.Labels) != 2 {
		t.Fatalf("input labels mutated = %+v", original.Labels)
	}
}

func TestProcessRejectsMissingDetector(t *testing.T) {
	if _, err := New(nil, nil, testProfiles(t)).Process(domainevent.Event{}, nil); err == nil {
		t.Fatal("Process() error = nil")
	}
}

func TestProcessAllowsUnconfiguredLearningDetector(t *testing.T) {
	detector := &detectorFake{}
	profiles := testProfiles(t)
	identity := profiles.Resolve(domainprocess.IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 7, StartTimeNS: 1}})
	if _, err := New(detector, nil, profiles).Process(domainevent.Event{ID: "event-a", Subject: identity.Process}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProcessSkipsLearningForProcesslessEvent(t *testing.T) {
	detector := &detectorFake{signals: []*domaindetection.Signal{{ID: "rule-a"}}}
	learning := &profileDetectorFake{signals: []*domaindetection.Signal{{ID: "model-a"}}}
	result, err := New(detector, learning, testProfiles(t)).Process(domainevent.Event{
		ID: "event-a", Behavior: domainevent.BehaviorNetworkConnect,
		Object: domainevent.Object{Kind: "socket", SocketAddress: "10.0.0.1:443"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signals) != 1 || result.Signals[0].ID != "rule-a" {
		t.Fatalf("signals = %+v", result.Signals)
	}
	if learning.snapshot.StableID != "" {
		t.Fatalf("learning detector received processless snapshot = %+v", learning.snapshot)
	}
}

func TestProcessRunsLearningOnlyForSemanticFeatureChanges(t *testing.T) {
	detector := &detectorFake{}
	profiles := testProfiles(t)
	identity := profiles.Resolve(domainprocess.IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 7, SensorExecID: "exec-a"}})
	learning := &profileDetectorFake{}
	service := New(detector, learning, profiles)

	events := []domainevent.Event{
		{ID: "exec", Behavior: domainevent.BehaviorProcessExec, Subject: identity.Process, SubjectPresent: true},
		{ID: "exec", Behavior: domainevent.BehaviorProcessExec, Subject: identity.Process, SubjectPresent: true},
		{ID: "fork", Behavior: domainevent.BehaviorProcessFork, Subject: identity.Process, SubjectPresent: true},
		{ID: "file-1", Behavior: "file.write", Subject: identity.Process, SubjectPresent: true, Object: domainevent.Object{FilePath: "/tmp/payload"}},
		{ID: "file-2", Behavior: "file.write", Subject: identity.Process, SubjectPresent: true, Object: domainevent.Object{FilePath: "/tmp/payload"}},
		{ID: "exit", Behavior: domainevent.BehaviorProcessExit, Subject: identity.Process, SubjectPresent: true},
	}
	for _, event := range events {
		if _, err := service.Process(event, nil); err != nil {
			t.Fatalf("Process(%s): %v", event.ID, err)
		}
	}
	if learning.calls != 2 {
		t.Fatalf("learning calls = %d, want 2 after duplicate exec", learning.calls)
	}
}

func TestProcessSerializesProfileObservationAndLearning(t *testing.T) {
	profiles := testProfiles(t)
	identity := profiles.Resolve(domainprocess.IdentityObservation{HostID: "host-a", Process: domainevent.Process{PID: 7, SensorExecID: "exec-a"}})
	learning := &profileDetectorFake{firstStarted: make(chan struct{}), secondEntered: make(chan struct{}), release: make(chan struct{})}
	service := New(&detectorFake{}, learning, profiles)
	firstDone := make(chan struct{})
	go func() {
		_, _ = service.Process(domainevent.Event{ID: "exec", Behavior: domainevent.BehaviorProcessExec, Subject: identity.Process, SubjectPresent: true}, nil)
		close(firstDone)
	}()
	<-learning.firstStarted
	secondDone := make(chan struct{})
	go func() {
		_, _ = service.Process(domainevent.Event{ID: "file", Behavior: "file.write", Subject: identity.Process, SubjectPresent: true, Object: domainevent.Object{FilePath: "/tmp/payload"}}, nil)
		close(secondDone)
	}()
	select {
	case <-learning.secondEntered:
		t.Fatal("second event entered Learning before first event completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(learning.release)
	<-firstDone
	<-secondDone
}

type detectorFake struct {
	event   domainevent.Event
	signals []*domaindetection.Signal
}

func (detector *detectorFake) Process(event domainevent.Event) []*domaindetection.Signal {
	detector.event = event
	return detector.signals
}

type profileDetectorFake struct {
	snapshot                             domainprocess.Snapshot
	signals                              []*domaindetection.Signal
	calls                                int
	callMu                               sync.Mutex
	firstStarted, secondEntered, release chan struct{}
}

func (detector *profileDetectorFake) Process(snapshot domainprocess.Snapshot) []*domaindetection.Signal {
	detector.callMu.Lock()
	detector.calls++
	call := detector.calls
	detector.callMu.Unlock()
	if call == 1 && detector.firstStarted != nil {
		close(detector.firstStarted)
		<-detector.release
	}
	if call == 2 && detector.secondEntered != nil {
		close(detector.secondEntered)
	}
	detector.snapshot = snapshot
	return detector.signals
}

func testProfiles(t *testing.T) *domainprocess.Profiles {
	t.Helper()
	profiles, err := domainprocess.NewProfiles(domainprocess.Limits{
		MaxProfiles: 8, MaxFiles: 4, MaxNetworks: 4, MaxEventRefs: 4,
		ExitGrace: time.Second, RetainedTTL: time.Minute, SweepInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return profiles
}
