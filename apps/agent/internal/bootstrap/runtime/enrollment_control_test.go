package runtime

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	appenrollment "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
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
	runner.revokeEnrollment = func(context.Context, sqlite.Enrollment, string) (string, time.Time, error) {
		return "", time.Time{}, context.DeadlineExceeded
	}
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	result := controller.Unenroll(t.Context(), appenrollment.UnenrollmentCommand{})
	enrollment, err := store.Enrollment(t.Context())
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if result.Status != "pending" || err != nil || enrollment.State != sqlite.StateUnenrolling || enrollment.RevocationConfirmed || activeErr != nil || !ok || source != sqlite.PolicySourceManaged {
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
	runner.revokeEnrollment = func(context.Context, sqlite.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	runner.setEndpointPolicy(standalone)
	flowStarted := make(chan struct{})
	var flowStartedOnce sync.Once
	runner.network = newNetworkSupervisor(t.Context(), func(ctx context.Context) { <-ctx.Done() }, func(ctx context.Context, _ sqlite.Enrollment) {
		flowStartedOnce.Do(func() { close(flowStarted) })
		<-ctx.Done()
		runner.policyAuthorityMu.Lock()
		runner.policyAuthorityMu.Unlock()
	})
	enrollment := sqlite.Enrollment{State: sqlite.StateManaged, AgentID: "agent-a"}
	runner.network.ApplyEnrollment(enrollment, managementContextForTest(t, enrollment.State))
	<-flowStarted
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	done := make(chan lifecycle.Result, 1)
	go func() {
		done <- controller.Unenroll(t.Context(), appenrollment.UnenrollmentCommand{})
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
	runner.revokeEnrollment = func(context.Context, sqlite.Enrollment, string) (string, time.Time, error) {
		return "", time.Time{}, context.DeadlineExceeded
	}
	controller := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	result := controller.Unenroll(t.Context(), appenrollment.UnenrollmentCommand{})
	got, readErr := store.Enrollment(t.Context())
	if result.Status != "pending" || readErr != nil || got.State != sqlite.StateUnenrolling || got.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v readErr=%v", result, got, readErr)
	}
	_, source, ok, activeErr := store.ActivePolicy(t.Context(), "endpoint")
	if activeErr != nil || !ok || source != sqlite.PolicySourceManaged {
		t.Fatalf("active source=%q ok=%t err=%v", source, ok, activeErr)
	}
}

func TestEnrollReturnsPendingWithoutRequestingAnotherCertificate(t *testing.T) {
	store, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enrollment := testRemoteEnrollment()
	if err := store.SetEnrolling(t.Context(), enrollment); err != nil {
		t.Fatal(err)
	}
	runner := &Coordinator{Config: config.Config{Local: config.LocalConfig{StatePath: t.TempDir()}}, managementRuntime: managementRuntime{localStore: store}}
	controller := newEnrollmentCoordinator(t.Context(), runner, nil)
	result := controller.Enroll(t.Context(), appenrollment.EnrollmentCommand{ManagerURL: "://invalid"})
	if result.Status != "pending" || !strings.Contains(result.Message, "already waiting") {
		t.Fatalf("result=%+v", result)
	}
}

func TestEnrollRejectsManagedAgentWithoutRequestingAnotherCertificate(t *testing.T) {
	store, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setManagedEnrollmentForTest(t, store)
	runner := &Coordinator{Config: config.Config{Local: config.LocalConfig{StatePath: t.TempDir()}}, managementRuntime: managementRuntime{localStore: store}}
	controller := newEnrollmentCoordinator(t.Context(), runner, nil)
	result := controller.Enroll(t.Context(), appenrollment.EnrollmentCommand{ManagerURL: "://invalid"})
	if result.Status != "rejected" || !strings.Contains(result.Message, "already managed") {
		t.Fatalf("result=%+v", result)
	}
}

func testRemoteEnrollment() sqlite.Enrollment {
	return sqlite.Enrollment{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42", ManagerURL: "https://manager.example", GatewayAddress: "gateway", TLSCAPath: "/ca", TLSCertPath: "/cert", TLSKeyPath: "/key"}
}

func setManagedEnrollmentForTest(t *testing.T, store *sqlite.Store) {
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
