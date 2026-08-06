package daemon

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestEnrollmentCoordinatorKeepsManagedAuthorityWhileRevocationIsPending(t *testing.T) {
	store := coordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "", time.Time{}, context.DeadlineExceeded
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))

	result := coordinator.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{})
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" || enrollment.State != localstore.StateUnenrolling || enrollment.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v", result, enrollment)
	}
	_, source, ok, err := store.ActivePolicy(t.Context(), "endpoint")
	if err != nil || !ok || source != localstore.PolicySourceManaged {
		t.Fatalf("active source=%q ok=%t err=%v", source, ok, err)
	}
}

func TestEnrollmentCoordinatorPersistsCompletionBeforeRevocation(t *testing.T) {
	store := coordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.reportUnenrollment = func(context.Context) (bool, error) { return true, nil }
	runner.revokeEnrollment = func(_ context.Context, _ localstore.Enrollment, tokenHash string) (string, time.Time, error) {
		completion, ok, err := store.UnenrollmentCompletion(t.Context())
		if err != nil || !ok || completion.Status != localstore.CompletionPrepared || completion.TokenHash != tokenHash {
			t.Fatalf("completion=%+v ok=%t err=%v", completion, ok, err)
		}
		return "receipt-a", time.Now().UTC(), nil
	}

	if result := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor)).Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{}); result.Status != "applied" {
		t.Fatalf("Unenroll() result=%+v", result)
	}
}

func TestEnrollmentCoordinatorRejectsEnrollmentBeforeRemoteRequestWhileCompletionIsPending(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})

	result := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor)).Enroll(t.Context(), agentcontrol.EnrollmentCommand{ManagerURL: "://invalid", Token: "token"})
	if result.Status != "pending" || !strings.Contains(result.Message, "completion") {
		t.Fatalf("Enroll() result=%+v", result)
	}
}

func TestEnrollmentCoordinatorUnenrollsMigratedLegacyEnrollment(t *testing.T) {
	store := legacyCoordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	var reportCalls atomic.Int32
	runner.reportUnenrollment = func(context.Context) (bool, error) {
		reportCalls.Add(1)
		return true, nil
	}
	runner.revokeEnrollment = func(_ context.Context, enrollment localstore.Enrollment, tokenHash string) (string, time.Time, error) {
		if tokenHash != "" || enrollment.EnrollmentID != "" || enrollment.CertificateSerial != "" {
			t.Fatalf("legacy revocation enrollment=%+v token hash=%q", enrollment, tokenHash)
		}
		return "legacy-receipt", time.Now().UTC(), nil
	}

	result := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor)).Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{})
	current, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "applied" || current.State != localstore.StateStandalone || reportCalls.Load() != 0 {
		t.Fatalf("result=%+v enrollment=%+v reportCalls=%d", result, current, reportCalls.Load())
	}
}

func TestEnrollmentCoordinatorDoesNotReportBeforeLocalCompletion(t *testing.T) {
	store := coordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	var reportCalls atomic.Int32
	runner.reportUnenrollment = func(context.Context) (bool, error) {
		reportCalls.Add(1)
		return true, nil
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	coordinator.completeUnenrollment = func(context.Context, string) error { return errors.New("sqlite commit failed") }

	if result := coordinator.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{}); result.Status != "rejected" {
		t.Fatalf("Unenroll() result=%+v", result)
	}
	if reportCalls.Load() != 0 {
		t.Fatalf("completion reports=%d, want 0", reportCalls.Load())
	}
}

func TestEnrollmentCoordinatorResumesConfirmedUnenrollmentWithoutRevocationRPC(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	var revokeCalls atomic.Int32
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		revokeCalls.Add(1)
		return "", time.Time{}, context.Canceled
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))

	if err := coordinator.Resume(t.Context()); err != nil {
		t.Fatal(err)
	}
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State != localstore.StateStandalone || revokeCalls.Load() != 0 {
		t.Fatalf("enrollment=%+v revoke calls=%d", enrollment, revokeCalls.Load())
	}
}

func TestEnrollmentCoordinatorNeverRestartsManagedFlowAfterRevocationConfirmation(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	var managedStarts atomic.Int32
	runner.network = newNetworkSupervisor(t.Context(), func(context.Context) {}, func(context.Context, localstore.Enrollment) {
		managedStarts.Add(1)
	})
	current, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(current.TLSCertPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current.TLSCertPath, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))

	if err := coordinator.Resume(t.Context()); err == nil {
		t.Fatal("Resume() error = nil, want credential cleanup failure")
	}
	if managedStarts.Load() != 0 || runner.network.Managed() {
		t.Fatalf("managed starts=%d managed=%t", managedStarts.Load(), runner.network.Managed())
	}
}

func TestEnrollmentCoordinatorDoesNotReconnectManagedWhenLocalCompletionFails(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	var managedStarts atomic.Int32
	runner.network = newNetworkSupervisor(t.Context(), func(context.Context) {}, func(context.Context, localstore.Enrollment) {
		managedStarts.Add(1)
	})
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	coordinator.completeUnenrollment = func(context.Context, string) error { return errors.New("sqlite commit failed") }

	if err := coordinator.Resume(t.Context()); err == nil {
		t.Fatal("Resume() error = nil, want local completion failure")
	}
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State != localstore.StateUnenrolling || !enrollment.RevocationConfirmed || managedStarts.Load() != 0 || runner.network.Managed() {
		t.Fatalf("enrollment=%+v managed starts=%d managed=%t", enrollment, managedStarts.Load(), runner.network.Managed())
	}
}

func TestEnrollmentCoordinatorSuccessfulUnenrollmentRemovesCredentials(t *testing.T) {
	store := coordinatorManagedStore(t)
	current, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current.TLSCAPath, current.TLSCertPath, current.TLSKeyPath} {
		if err := os.WriteFile(path, []byte("credential"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))

	if result := coordinator.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{}); result.Status != "applied" {
		t.Fatalf("Unenroll() result=%+v", result)
	}
	for _, path := range []string{current.TLSCAPath, current.TLSCertPath, current.TLSKeyPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("credential %q still exists: %v", path, err)
		}
	}
}

func TestEnrollmentCoordinatorCompletesConfirmedUnenrollmentAfterRequestCancellation(t *testing.T) {
	store := coordinatorManagedStore(t)
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	sensor := &requestCancellationSensor{applyStarted: applyStarted, releaseApply: releaseApply}
	runner := newEndpointPolicyRunner(t, store, sensor)
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(sensor))
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	done := make(chan agentcontrol.Result, 1)
	go func() { done <- coordinator.Unenroll(requestCtx, agentcontrol.UnenrollmentCommand{}) }()

	<-applyStarted
	cancelRequest()
	close(releaseApply)
	result := <-done
	enrollment, err := store.Enrollment(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "applied" || enrollment.State != localstore.StateStandalone {
		t.Fatalf("result=%+v enrollment=%+v", result, enrollment)
	}
}

func TestEnrollmentCoordinatorDoesNotHoldPolicyAuthorityWhileReconcilingStandalone(t *testing.T) {
	store := coordinatorManagedStore(t)
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{health: contract.Health{Backend: "fake"}})
	runner.revokeEnrollment = func(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
		return "receipt-a", time.Now().UTC(), nil
	}
	apply := make(chan struct{})
	releaseApply := make(chan struct{})
	supervisor := sensorruntime.NewSubscriptionSupervisor(
		&blockingCollectionRuntime{apply: apply, releaseApply: releaseApply},
		runner.currentCollectionIntent(), sensorruntime.RetryOptions{},
	)
	supervisor.OnApplied(func(context.Context, contract.CollectionIntent) error {
		runner.policyAuthorityMu.Lock()
		runner.policyAuthorityMu.Unlock()
		return nil
	})
	runner.setSensorSupervisor(supervisor)
	supervisor.Start(t.Context())
	<-apply
	coordinator := newEnrollmentCoordinator(t.Context(), runner, sensorruntime.New(runner.Sensor))
	done := make(chan agentcontrol.Result, 1)
	go func() { done <- coordinator.Unenroll(t.Context(), agentcontrol.UnenrollmentCommand{}) }()
	waitForRevocationConfirmation(t, store)
	close(releaseApply)

	select {
	case result := <-done:
		if result.Status != "applied" {
			t.Fatalf("Unenroll() result=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("Unenroll() deadlocked policy authority with sensor reconcile callback")
	}
}

type requestCancellationSensor struct {
	healthOnlySensor
	applyStarted chan struct{}
	releaseApply chan struct{}
}

type blockingCollectionRuntime struct {
	apply        chan struct{}
	releaseApply chan struct{}
	first        atomic.Bool
}

func (r *blockingCollectionRuntime) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	if r.first.CompareAndSwap(false, true) {
		close(r.apply)
		<-r.releaseApply
	}
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (r *blockingCollectionRuntime) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	events := make(chan contract.EventEnvelope)
	go func() {
		defer close(events)
		<-ctx.Done()
	}()
	return events, nil
}

func waitForRevocationConfirmation(t *testing.T, store *localstore.Store) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		enrollment, err := store.Enrollment(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if enrollment.RevocationConfirmed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("revocation confirmation was not persisted")
}

func (s *requestCancellationSensor) Apply(ctx context.Context, _ contract.CollectionIntent) (contract.ApplyResult, error) {
	close(s.applyStarted)
	select {
	case <-s.releaseApply:
		return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
	case <-ctx.Done():
		return contract.ApplyResult{}, ctx.Err()
	}
}

func coordinatorManagedStore(t *testing.T) *localstore.Store {
	t.Helper()
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	return store
}

func legacyCoordinatorManagedStore(t *testing.T) *localstore.Store {
	t.Helper()
	root := t.TempDir()
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE enrollment SET enrollment_id=NULL, certificate_serial=NULL,
manager_url=NULL, unenrollment_protocol='legacy_mtls' WHERE singleton=1 AND state='managed'`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}
