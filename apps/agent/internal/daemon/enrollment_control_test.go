package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestEnrollmentControllerKeepsManagedAuthorityUntilRevocation(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "", time.Time{}, context.DeadlineExceeded
	}
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	result := controller.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{})
	enrollment, err := store.Enrollment(t.Context())
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if result.Status != "pending" || err != nil || enrollment.State != localstore.StateUnenrolling || enrollment.RevocationConfirmed || activeErr != nil || !ok || source != localstore.PolicySourceManaged {
		t.Fatalf("result=%+v enrollment=%+v source=%q ok=%t errors=%v/%v", result, enrollment, source, ok, err, activeErr)
	}
}

func TestUnenrollDoesNotWaitForManagedFlowWhileHoldingPolicyAuthority(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	standalone := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	runner.setEndpointPolicy(standalone)
	flowStarted := make(chan struct{})
	var flowStartedOnce sync.Once
	runner.network = newNetworkSupervisor(t.Context(), func(ctx context.Context) { <-ctx.Done() }, func(ctx context.Context, _ localstore.Enrollment) {
		flowStartedOnce.Do(func() { close(flowStarted) })
		<-ctx.Done()
		runner.policyAuthorityMu.Lock()
		runner.policyAuthorityMu.Unlock()
	})
	enrollment := localstore.Enrollment{State: localstore.StateManaged, AgentID: "agent-a"}
	runner.network.ApplyEnrollment(enrollment, managementContextForTest(t, enrollment.State))
	<-flowStarted
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	done := make(chan agentcontrol.Result, 1)
	go func() {
		done <- controller.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{})
	}()
	select {
	case result := <-done:
		if result.Status != "applied" {
			t.Fatalf("Unenroll() result = %+v", result)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Unenroll blocked while managed flow waited for policy authority")
	}
}

func TestUnenrollRemainsManagedWhenManagerRevocationIsUnconfirmed(t *testing.T) {
	store := openEndpointPolicyStore(t)
	defer store.Close()
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "", time.Time{}, context.DeadlineExceeded
	}
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	result := controller.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{})
	got, readErr := store.Enrollment(t.Context())
	if result.Status != "pending" || readErr != nil || got.State != localstore.StateUnenrolling || got.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v readErr=%v", result, got, readErr)
	}
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if activeErr != nil || !ok || source != localstore.PolicySourceManaged {
		t.Fatalf("active source=%q ok=%t err=%v", source, ok, activeErr)
	}
}

func TestEnrollReturnsPendingWithoutRequestingAnotherCertificate(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enrollment := testRemoteEnrollment()
	if err := store.SetEnrolling(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	runner := &AgentRuntime{Config: config.Config{Local: config.LocalConfig{StatePath: t.TempDir()}}, localStore: store}
	controller := newEnrollmentCoordinator(t.Context(), runner, nil)
	result := controller.Enroll(t.Context(), agentcontrol.EnrollmentCommand{ManagerURL: "://invalid"})
	if result.Status != "pending" || !strings.Contains(result.Message, "already waiting") {
		t.Fatalf("result=%+v", result)
	}
}

func TestEnrollRejectsManagedAgentWithoutRequestingAnotherCertificate(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setManagedEnrollmentForTest(t, store)
	runner := &AgentRuntime{Config: config.Config{Local: config.LocalConfig{StatePath: t.TempDir()}}, localStore: store}
	controller := newEnrollmentCoordinator(t.Context(), runner, nil)
	result := controller.Enroll(t.Context(), agentcontrol.EnrollmentCommand{ManagerURL: "://invalid"})
	if result.Status != "rejected" || !strings.Contains(result.Message, "already managed") {
		t.Fatalf("result=%+v", result)
	}
}

func testRemoteEnrollment() localstore.Enrollment {
	return localstore.Enrollment{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42", ManagerURL: "https://manager.example", GatewayAddress: "gateway", TLSCAPath: "/ca", TLSCertPath: "/cert", TLSKeyPath: "/key"}
}

func setManagedEnrollmentForTest(t *testing.T, store *localstore.Store) {
	t.Helper()
	enrollment := testRemoteEnrollment()
	credentialDir := t.TempDir()
	enrollment.TLSCAPath = filepath.Join(credentialDir, "ca.pem")
	enrollment.TLSCertPath = filepath.Join(credentialDir, "agent.pem")
	enrollment.TLSKeyPath = filepath.Join(credentialDir, "agent-key.pem")
	if err := store.SetEnrolling(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	policy := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	policy.PolicyID = "managed"
	if err := agentpolicy.ActivateManagedEndpointPolicy(t.Context(), store, policy); err != nil {
		t.Fatal(err)
	}
}
