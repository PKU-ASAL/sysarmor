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
	profiles.Observe(domainevent.Event{
		ID: "event-a", Behavior: domainevent.BehaviorProcessExec, SubjectPresent: true, Subject: identity.Process,
	})

	value, err := (&runtimeHealthSource{health: runner.healthRuntime()}).Detection(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if value.Learning.Profiles.Active != 1 {
		t.Fatalf("profile health = %+v", value.Learning.Profiles)
	}
}
