package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

type recordingEnrollmentStore struct {
	enrollment       localstore.Enrollment
	completion       localstore.UnenrollmentCompletion
	completionExists bool
	stats            localstore.Stats
	setEnrollingErr  error
	completeErr      error
	recordedError    string
	completeCalls    int
}

func (s *recordingEnrollmentStore) Enrollment(context.Context) (localstore.Enrollment, error) {
	return s.enrollment, nil
}

func (s *recordingEnrollmentStore) Stats(context.Context) (localstore.Stats, error) {
	return s.stats, nil
}

func (s *recordingEnrollmentStore) SetEnrolling(_ context.Context, enrollment localstore.Enrollment) error {
	if s.setEnrollingErr != nil {
		return s.setEnrollingErr
	}
	enrollment.State = localstore.StateEnrolling
	s.enrollment = enrollment
	return nil
}

func (s *recordingEnrollmentStore) BeginUnenrollment(context.Context) (localstore.Enrollment, error) {
	s.enrollment.State = localstore.StateUnenrolling
	return s.enrollment, nil
}

func (s *recordingEnrollmentStore) PrepareUnenrollment(_ context.Context, token, tokenHash string) (localstore.Enrollment, error) {
	s.enrollment.State = localstore.StateUnenrolling
	s.completion = localstore.UnenrollmentCompletion{Token: token, TokenHash: tokenHash, Status: localstore.CompletionPrepared}
	s.completionExists = true
	return s.enrollment, nil
}

func (s *recordingEnrollmentStore) UnenrollmentCompletion(context.Context) (localstore.UnenrollmentCompletion, bool, error) {
	return s.completion, s.completionExists, nil
}

func (s *recordingEnrollmentStore) RecordUnenrollmentError(_ context.Context, message string) error {
	s.recordedError = message
	return nil
}

func (s *recordingEnrollmentStore) ConfirmEnrollmentRevocation(_ context.Context, receipt string, revokedAt time.Time) error {
	s.enrollment.RevocationConfirmed = true
	s.enrollment.RevocationReceipt = receipt
	s.enrollment.RevokedAt = revokedAt
	return nil
}

func (s *recordingEnrollmentStore) CompleteUnenrollment(context.Context, string) error {
	s.completeCalls++
	if s.completeErr != nil {
		return s.completeErr
	}
	s.enrollment = localstore.Enrollment{State: localstore.StateStandalone}
	return nil
}

type recordingEnrollmentRuntime struct {
	identity         EnrollmentIdentity
	preparation      EnrollmentPreparation
	prepareErr       error
	revokeErr        error
	restoreErr       error
	removeErr        error
	reportErr        error
	rollbackCalls    int
	stopNetworkCalls int
	restoreCalls     int
	reportCalls      int
	finalizeCalls    int
	authorityCalls   int
	reconcileStates  []localstore.EnrollmentState
	reconcileErr     error
}

func (r *recordingEnrollmentRuntime) EnrollmentIdentity() EnrollmentIdentity { return r.identity }

func (r *recordingEnrollmentRuntime) PrepareEnrollment(context.Context, string, string) (EnrollmentPreparation, error) {
	return r.preparation, r.prepareErr
}

func (r *recordingEnrollmentRuntime) RollbackEnrollment(EnrollmentPreparation, error) error {
	r.rollbackCalls++
	return nil
}

func (r *recordingEnrollmentRuntime) FinalizeEnrollment(EnrollmentPreparation) { r.finalizeCalls++ }

func (r *recordingEnrollmentRuntime) StopEnrollmentNetwork() { r.stopNetworkCalls++ }

func (r *recordingEnrollmentRuntime) WithPolicyAuthority(run func() error) error {
	r.authorityCalls++
	return run()
}

func (r *recordingEnrollmentRuntime) ReconcileEnrollment(enrollment localstore.Enrollment) error {
	r.reconcileStates = append(r.reconcileStates, enrollment.State)
	return r.reconcileErr
}

func (r *recordingEnrollmentRuntime) RevokeEnrollment(context.Context, localstore.Enrollment, string) (string, time.Time, error) {
	return "receipt-a", time.Unix(10, 0).UTC(), r.revokeErr
}

func (r *recordingEnrollmentRuntime) RestoreStandalonePolicy(ctx context.Context, activate func(context.Context) error) error {
	r.restoreCalls++
	if r.restoreErr != nil {
		return r.restoreErr
	}
	return activate(ctx)
}

func (r *recordingEnrollmentRuntime) RemoveEnrollmentCredentials(localstore.Enrollment) error {
	return r.removeErr
}

func (r *recordingEnrollmentRuntime) ReportUnenrollmentCompletion(context.Context) (bool, error) {
	r.reportCalls++
	return r.reportErr == nil, r.reportErr
}

func TestEnrollmentCoordinatorKeepsManagedStateUntilRevocationConfirmed(t *testing.T) {
	store, runtime := managedEnrollmentFixture()
	runtime.revokeErr = context.DeadlineExceeded
	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != "pending" || store.enrollment.State != localstore.StateUnenrolling || store.enrollment.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if runtime.restoreCalls != 0 || runtime.stopNetworkCalls != 0 || !strings.Contains(store.recordedError, "deadline") {
		t.Fatalf("runtime=%+v recorded error=%q", runtime, store.recordedError)
	}
}

func TestEnrollmentCoordinatorRestoresStandaloneOnlyAfterRevocation(t *testing.T) {
	store, runtime := managedEnrollmentFixture()
	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != "applied" || store.enrollment.State != localstore.StateStandalone || store.completeCalls != 1 {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if runtime.restoreCalls != 1 || runtime.stopNetworkCalls != 1 || runtime.reportCalls != 1 || runtime.authorityCalls != 1 {
		t.Fatalf("runtime=%+v", runtime)
	}
	if len(runtime.reconcileStates) != 1 || runtime.reconcileStates[0] != localstore.StateStandalone {
		t.Fatalf("reconcile states=%v", runtime.reconcileStates)
	}
}

func TestEnrollmentCoordinatorPolicyRestoreFailureRemainsUnenrolling(t *testing.T) {
	store, runtime := managedEnrollmentFixture()
	runtime.restoreErr = errors.New("restore standalone policy")
	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != "rejected" || store.enrollment.State != localstore.StateUnenrolling || !store.enrollment.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if store.completeCalls != 0 || len(runtime.reconcileStates) != 0 {
		t.Fatalf("runtime=%+v complete calls=%d", runtime, store.completeCalls)
	}
}

func TestEnrollmentCoordinatorCompletionFailureIsPendingAfterLocalCompletion(t *testing.T) {
	store, runtime := managedEnrollmentFixture()
	runtime.reportErr = errors.New("manager unavailable")
	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != "pending" || store.enrollment.State != localstore.StateStandalone || runtime.reportCalls != 1 {
		t.Fatalf("result=%+v enrollment=%+v runtime=%+v", result, store.enrollment, runtime)
	}
	if !strings.Contains(result.Message, "manager completion is pending") {
		t.Fatalf("message=%q", result.Message)
	}
}

func TestEnrollmentCoordinatorRollsBackCredentialsWhenStoreRejectsEnrollment(t *testing.T) {
	store := &recordingEnrollmentStore{enrollment: localstore.Enrollment{State: localstore.StateStandalone}, setEnrollingErr: errors.New("sqlite commit failed")}
	runtime := &recordingEnrollmentRuntime{
		identity: EnrollmentIdentity{TenantID: "local", AgentID: "device-a"},
		preparation: EnrollmentPreparation{Enrollment: localstore.Enrollment{
			State: localstore.StateEnrolling, TenantID: "tenant-a", AgentID: "agent-a", ManagerURL: "https://manager.example",
		}},
	}
	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != "rejected" || runtime.rollbackCalls != 1 || store.enrollment.State != localstore.StateStandalone {
		t.Fatalf("result=%+v store=%+v runtime=%+v", result, store, runtime)
	}
	if len(runtime.reconcileStates) != 1 || runtime.reconcileStates[0] != localstore.StateStandalone {
		t.Fatalf("reconcile states=%v", runtime.reconcileStates)
	}
}

func TestEnrollmentCoordinatorReconcilesCommittedEnrollment(t *testing.T) {
	store := &recordingEnrollmentStore{enrollment: localstore.Enrollment{State: localstore.StateStandalone}}
	runtime := &recordingEnrollmentRuntime{
		identity: EnrollmentIdentity{TenantID: "local", AgentID: "device-a"},
		preparation: EnrollmentPreparation{Enrollment: localstore.Enrollment{
			State: localstore.StateEnrolling, TenantID: "tenant-a", AgentID: "agent-a", ManagerURL: "https://manager.example",
		}},
	}

	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != "pending" || store.enrollment.State != localstore.StateEnrolling || runtime.finalizeCalls != 1 || runtime.rollbackCalls != 0 {
		t.Fatalf("result=%+v store=%+v runtime=%+v", result, store, runtime)
	}
	if len(runtime.reconcileStates) != 1 || runtime.reconcileStates[0] != localstore.StateEnrolling {
		t.Fatalf("reconcile states=%v", runtime.reconcileStates)
	}
}

func TestEnrollmentCoordinatorKeepsCommittedEnrollmentWhenReconcileFails(t *testing.T) {
	store := &recordingEnrollmentStore{enrollment: localstore.Enrollment{State: localstore.StateStandalone}}
	runtime := &recordingEnrollmentRuntime{
		identity:     EnrollmentIdentity{TenantID: "local", AgentID: "device-a"},
		reconcileErr: errors.New("runtime unavailable"),
		preparation: EnrollmentPreparation{Enrollment: localstore.Enrollment{
			State: localstore.StateEnrolling, TenantID: "tenant-a", AgentID: "agent-a", ManagerURL: "https://manager.example",
		}},
	}

	result := NewEnrollmentCoordinator(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != "pending" || !strings.Contains(result.Message, "runtime reconciliation is pending") {
		t.Fatalf("result=%+v", result)
	}
	if store.enrollment.State != localstore.StateEnrolling || runtime.finalizeCalls != 1 || runtime.rollbackCalls != 0 {
		t.Fatalf("store=%+v runtime=%+v", store, runtime)
	}
}

func managedEnrollmentFixture() (*recordingEnrollmentStore, *recordingEnrollmentRuntime) {
	store := &recordingEnrollmentStore{enrollment: localstore.Enrollment{
		State: localstore.StateManaged, TenantID: "tenant-a", AgentID: "agent-a",
		EnrollmentID: "enrollment-a", CertificateSerial: "42", ManagerURL: "https://manager.example",
		UnenrollmentProtocol: localstore.UnenrollmentProtocolCompletionV1,
	}}
	runtime := &recordingEnrollmentRuntime{identity: EnrollmentIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	return store, runtime
}
