package runtime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
)

func TestNetworkSupervisorSwitchesStandaloneAndManagedFlowsWithoutOverlap(t *testing.T) {
	starts := make(chan string, 3)
	var active atomic.Int32
	var overlap atomic.Bool
	start := func(name string) func(context.Context) {
		return func(ctx context.Context) {
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			starts <- name
			<-ctx.Done()
			active.Add(-1)
		}
	}
	supervisor := newNetworkSupervisor(t.Context(), start("standalone"), func(ctx context.Context, _ sqlite.Enrollment) {
		start("managed")(ctx)
	})
	supervisor.ApplyEnrollment(sqlite.Enrollment{State: sqlite.StateStandalone}, managementContextForTest(t, sqlite.StateStandalone))
	waitNetworkMode(t, starts, "standalone")
	supervisor.ApplyEnrollment(sqlite.Enrollment{State: sqlite.StateEnrolling, AgentID: "agent-a", GatewayAddress: "gateway"}, managementContextForTest(t, sqlite.StateEnrolling))
	waitNetworkMode(t, starts, "managed")
	supervisor.ApplyEnrollment(sqlite.Enrollment{State: sqlite.StateStandalone}, managementContextForTest(t, sqlite.StateStandalone))
	waitNetworkMode(t, starts, "standalone")
	supervisor.Stop()
	if overlap.Load() || active.Load() != 0 {
		t.Fatalf("network flows overlapped=%t active=%d", overlap.Load(), active.Load())
	}
}

func TestNetworkSupervisorAppliesEnrollmentIdempotently(t *testing.T) {
	starts := make(chan struct{}, 3)
	supervisor := newNetworkSupervisor(context.Background(), func(context.Context) {}, func(ctx context.Context, enrollment sqlite.Enrollment) {
		starts <- struct{}{}
		<-ctx.Done()
	})
	enrollment := sqlite.Enrollment{State: sqlite.StateManaged, AgentID: "a", GatewayAddress: "g"}
	mode := managementContextForTest(t, enrollment.State)
	supervisor.ApplyEnrollment(enrollment, mode)
	waitStart(t, starts)
	supervisor.ApplyEnrollment(enrollment, mode)
	select {
	case <-starts:
		t.Fatal("identical enrollment restarted network")
	case <-time.After(10 * time.Millisecond):
	}
	enrollment.GatewayAddress = "g2"
	supervisor.ApplyEnrollment(enrollment, mode)
	waitStart(t, starts)
	supervisor.Stop()
	if supervisor.Managed() {
		t.Fatal("supervisor still managed")
	}
}

func TestNetworkSupervisorStartsWhileEnrollmentAwaitsPolicy(t *testing.T) {
	starts := make(chan struct{}, 1)
	supervisor := newNetworkSupervisor(t.Context(), func(context.Context) {}, func(ctx context.Context, enrollment sqlite.Enrollment) {
		starts <- struct{}{}
		<-ctx.Done()
	})
	supervisor.ApplyEnrollment(sqlite.Enrollment{State: sqlite.StateEnrolling, AgentID: "agent-a", GatewayAddress: "gateway"}, managementContextForTest(t, sqlite.StateEnrolling))
	waitStart(t, starts)
	supervisor.Stop()
}

func TestNetworkSupervisorPromotesWithoutRestartingConnection(t *testing.T) {
	starts := make(chan struct{}, 2)
	supervisor := newNetworkSupervisor(t.Context(), func(context.Context) {}, func(ctx context.Context, enrollment sqlite.Enrollment) {
		starts <- struct{}{}
		<-ctx.Done()
	})
	enrollment := sqlite.Enrollment{State: sqlite.StateEnrolling, AgentID: "agent-a", GatewayAddress: "gateway"}
	supervisor.ApplyEnrollment(enrollment, managementContextForTest(t, enrollment.State))
	waitStart(t, starts)
	enrollment.State = sqlite.StateManaged
	if !supervisor.PromoteEnrollment(enrollment, managementContextForTest(t, enrollment.State)) {
		t.Fatal("managed enrollment promotion was not accepted")
	}
	select {
	case <-starts:
		t.Fatal("promotion restarted active connection")
	case <-time.After(20 * time.Millisecond):
	}
	if !supervisor.Managed() {
		t.Fatal("promotion stopped active connection")
	}
	supervisor.Stop()
}

func managementContextForTest(t *testing.T, state sqlite.EnrollmentState) management.Context {
	t.Helper()
	mode, err := management.Resolve(state)
	if err != nil {
		t.Fatal(err)
	}
	return mode
}

func waitStart(t *testing.T, starts <-chan struct{}) {
	t.Helper()
	select {
	case <-starts:
	case <-time.After(time.Second):
		t.Fatal("network did not start")
	}
}

func waitNetworkMode(t *testing.T, starts <-chan string, want string) {
	t.Helper()
	select {
	case got := <-starts:
		if got != want {
			t.Fatalf("network mode=%q, want %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("network mode %q did not start", want)
	}
}
