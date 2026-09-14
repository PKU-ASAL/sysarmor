package runtime

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
)

func TestRuntimeHealthSourceMarksMissingStorageUnavailable(t *testing.T) {
	value, err := (&runtimeHealthSource{health: runtimeHealth{management: &managementRuntime{}}}).Storage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.Available {
		t.Fatalf("storage=%+v", value)
	}
}

func TestRuntimeHealthSourceIncludesProcessProfileMetrics(t *testing.T) {
	runner := &Coordinator{Config: config.Config{Agent: config.AgentConfig{ID: "agent-a", HostID: "host-a"}}}
	runner.wireComponents()
	installTestDetection(t, runner)
	profiles, err := domainprocess.NewProfiles(processProfileLimits(runner.Config))
	if err != nil {
		t.Fatal(err)
	}
	runner.processProfiles = profiles
	runner.managementState.processProfiles = profiles
	identity := profiles.Resolve(domainprocess.IdentityObservation{
		HostID: "host-a", Process: domainevent.Process{PID: 1, SensorExecID: "exec-a"},
	})
	observation, ok := profiles.ObserveChanges(domainevent.Event{
		ID: "event-a", Behavior: domainevent.BehaviorProcessExec, SubjectPresent: true, Subject: identity.Process,
	})
	if !ok {
		t.Fatal("process profile observation was not recorded")
	}
	profiles.MarkScored(observation.StableID, observation.FeatureRevision)

	value, err := (&runtimeHealthSource{health: runner.healthRuntime()}).Detection(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.Learning.Profiles.Active != 1 {
		t.Fatalf("profile health = %+v", value.Learning.Profiles)
	}
	if value.Learning.Profiles.ProfileObservations != 1 || value.Learning.Profiles.FeatureUpdates != 1 || value.Learning.Profiles.LearningScoreCalls != 1 {
		t.Fatalf("profile scheduling health = %+v", value.Learning.Profiles)
	}
}
