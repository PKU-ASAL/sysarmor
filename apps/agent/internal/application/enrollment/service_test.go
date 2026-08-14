package enrollment

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type recordingStore struct {
	enrollment       ports.Enrollment
	completion       ports.UnenrollmentCompletion
	completionExists bool
	stats            ports.EnrollmentStats
	setEnrollingErr  error
	completeErr      error
	recordedError    string
	completeCalls    int
}

func (s *recordingStore) Enrollment(context.Context) (ports.Enrollment, error) {
	return s.enrollment, nil
}

func (s *recordingStore) Stats(context.Context) (ports.EnrollmentStats, error) {
	return s.stats, nil
}

func (s *recordingStore) SetEnrolling(_ context.Context, enrollment ports.Enrollment) error {
	if s.setEnrollingErr != nil {
		return s.setEnrollingErr
	}
	enrollment.State = management.StateEnrolling
	s.enrollment = enrollment
	return nil
}

func (s *recordingStore) PrepareUnenrollment(_ context.Context, token, tokenHash string) (ports.Enrollment, ports.UnenrollmentCompletion, error) {
	s.enrollment.State = management.StateUnenrolling
	if !s.completionExists {
		s.completion = ports.UnenrollmentCompletion{Token: token, TokenHash: tokenHash, Status: ports.CompletionPrepared}
		s.completionExists = true
	}
	return s.enrollment, s.completion, nil
}

func (s *recordingStore) UnenrollmentCompletion(context.Context) (ports.UnenrollmentCompletion, bool, error) {
	return s.completion, s.completionExists, nil
}

func (s *recordingStore) RecordUnenrollmentError(_ context.Context, message string) error {
	s.recordedError = message
	return nil
}

func (s *recordingStore) ConfirmEnrollmentRevocation(_ context.Context, receipt string, revokedAt time.Time) error {
	s.enrollment.RevocationConfirmed = true
	s.enrollment.RevocationReceipt = receipt
	s.enrollment.RevokedAt = revokedAt
	return nil
}

func (s *recordingStore) CompleteUnenrollment(context.Context, string) error {
	s.completeCalls++
	if s.completeErr != nil {
		return s.completeErr
	}
	s.enrollment = ports.Enrollment{State: management.StateStandalone}
	return nil
}

type recordingRuntime struct {
	identity         ports.EnrollmentIdentity
	preparation      ports.EnrollmentPreparation
	revokeErr        error
	restoreErr       error
	reportErr        error
	rollbackCalls    int
	stopNetworkCalls int
	restoreCalls     int
	reportCalls      int
	finalizeCalls    int
	finalizeErr      error
	authorityCalls   int
	reconcileStates  []management.State
	reconcileErr     error
	prepareReturned  func()
	revokeReturned   func()
}

type recordingPreparation struct {
	enrollment ports.Enrollment
}

func (p recordingPreparation) PreparedEnrollment() ports.Enrollment { return p.enrollment }

func (r *recordingRuntime) Identity() ports.EnrollmentIdentity { return r.identity }

func (r *recordingRuntime) PrepareEnrollment(context.Context, string, string) (ports.EnrollmentPreparation, error) {
	if r.prepareReturned != nil {
		r.prepareReturned()
	}
	return r.preparation, nil
}

func (r *recordingRuntime) RollbackEnrollment(ports.EnrollmentPreparation, error) error {
	r.rollbackCalls++
	return nil
}

func (r *recordingRuntime) FinalizeEnrollment(ports.EnrollmentPreparation) error {
	r.finalizeCalls++
	return r.finalizeErr
}
func (r *recordingRuntime) StopEnrollmentNetwork() { r.stopNetworkCalls++ }

func (r *recordingRuntime) WithPolicyAuthority(run func() error) error {
	r.authorityCalls++
	return run()
}

func (r *recordingRuntime) ReconcileEnrollment(enrollment ports.Enrollment) error {
	r.reconcileStates = append(r.reconcileStates, enrollment.State)
	return r.reconcileErr
}

func (r *recordingRuntime) RevokeEnrollment(context.Context, ports.Enrollment, string) (string, time.Time, error) {
	if r.revokeReturned != nil {
		r.revokeReturned()
	}
	return "receipt-a", time.Unix(10, 0).UTC(), r.revokeErr
}

func (r *recordingRuntime) RestoreStandalonePolicy(ctx context.Context, activate func(context.Context) error) error {
	r.restoreCalls++
	if r.restoreErr != nil {
		return r.restoreErr
	}
	return activate(ctx)
}

func (r *recordingRuntime) RemoveEnrollmentCredentials(ports.Enrollment) error { return nil }

func (r *recordingRuntime) ReportUnenrollmentCompletion(context.Context) (bool, error) {
	r.reportCalls++
	return r.reportErr == nil, r.reportErr
}

func TestServiceKeepsManagedStateUntilRevocationConfirmed(t *testing.T) {
	store, runtime := managedFixture()
	runtime.revokeErr = context.DeadlineExceeded
	result := NewService(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != lifecycle.StatusPending || store.enrollment.State != management.StateUnenrolling || store.enrollment.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if runtime.restoreCalls != 0 || runtime.stopNetworkCalls != 0 || !strings.Contains(store.recordedError, "deadline") {
		t.Fatalf("runtime=%+v recorded error=%q", runtime, store.recordedError)
	}
}

func TestServiceRestoresStandaloneOnlyAfterRevocation(t *testing.T) {
	store, runtime := managedFixture()
	result := NewService(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != lifecycle.StatusApplied || store.enrollment.State != management.StateStandalone || store.completeCalls != 1 {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if runtime.restoreCalls != 1 || runtime.stopNetworkCalls != 1 || runtime.reportCalls != 1 || runtime.authorityCalls != 1 {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestServicePolicyRestoreFailureRemainsUnenrolling(t *testing.T) {
	store, runtime := managedFixture()
	runtime.restoreErr = errors.New("restore standalone policy")
	result := NewService(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != lifecycle.StatusRejected || store.enrollment.State != management.StateUnenrolling || !store.enrollment.RevocationConfirmed {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
	if store.completeCalls != 0 || len(runtime.reconcileStates) != 0 {
		t.Fatalf("runtime=%+v complete calls=%d", runtime, store.completeCalls)
	}
}

func TestServiceCompletionFailureIsPendingAfterLocalCompletion(t *testing.T) {
	store, runtime := managedFixture()
	runtime.reportErr = errors.New("manager unavailable")
	result := NewService(t.Context(), store, runtime).Unenroll(t.Context(), UnenrollmentCommand{})

	if result.Status != lifecycle.StatusPending || store.enrollment.State != management.StateStandalone || runtime.reportCalls != 1 {
		t.Fatalf("result=%+v enrollment=%+v runtime=%+v", result, store.enrollment, runtime)
	}
}

func TestServiceRollsBackCredentialsWhenStoreRejectsEnrollment(t *testing.T) {
	store := &recordingStore{enrollment: ports.Enrollment{State: management.StateStandalone}, setEnrollingErr: errors.New("sqlite commit failed")}
	runtime := enrollmentRuntimeFixture()
	result := NewService(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != lifecycle.StatusRejected || runtime.rollbackCalls != 1 || store.enrollment.State != management.StateStandalone {
		t.Fatalf("result=%+v store=%+v runtime=%+v", result, store, runtime)
	}
	if len(runtime.reconcileStates) != 1 || runtime.reconcileStates[0] != management.StateStandalone {
		t.Fatalf("reconcile states=%v", runtime.reconcileStates)
	}
}

func TestServiceKeepsCommittedEnrollmentWhenReconcileFails(t *testing.T) {
	store := &recordingStore{enrollment: ports.Enrollment{State: management.StateStandalone}}
	runtime := enrollmentRuntimeFixture()
	runtime.reconcileErr = errors.New("runtime unavailable")
	result := NewService(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != lifecycle.StatusPending || !strings.Contains(result.Message, "runtime reconciliation is pending") {
		t.Fatalf("result=%+v", result)
	}
	if store.enrollment.State != management.StateEnrolling || runtime.finalizeCalls != 1 || runtime.rollbackCalls != 0 {
		t.Fatalf("store=%+v runtime=%+v", store, runtime)
	}
}

func TestServiceReportsFinalizeFailureAfterCommit(t *testing.T) {
	store := &recordingStore{enrollment: ports.Enrollment{State: management.StateStandalone}}
	runtime := enrollmentRuntimeFixture()
	runtime.finalizeErr = errors.New("pending key cleanup failed")
	result := NewService(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != lifecycle.StatusPending || !strings.Contains(result.Message, "pending key cleanup failed") {
		t.Fatalf("result=%+v", result)
	}
}

func TestServiceSelectsManagedHistoryBoundary(t *testing.T) {
	tests := []struct {
		name          string
		uploadHistory bool
		wantSequence  uint64
	}{
		{name: "new events only", wantSequence: 42},
		{name: "upload history", uploadHistory: true, wantSequence: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &recordingStore{
				enrollment: ports.Enrollment{State: management.StateStandalone},
				stats:      ports.EnrollmentStats{OldestEventSequence: 7, LatestEventSequence: 41},
			}
			runtime := enrollmentRuntimeFixture()
			result := NewService(t.Context(), store, runtime).Enroll(t.Context(), EnrollmentCommand{
				ManagerURL: "https://manager.example", Token: "token-a", UploadHistory: tt.uploadHistory,
			})
			if result.Status != lifecycle.StatusPending || store.enrollment.ManagedFromSequence != tt.wantSequence {
				t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
			}
		})
	}
}

func TestServiceCommitsEnrollmentAfterRemoteSuccessCancelsRequest(t *testing.T) {
	requestCtx, cancel := context.WithCancel(t.Context())
	store := &contextCheckingStore{recordingStore: recordingStore{
		enrollment: ports.Enrollment{State: management.StateStandalone},
	}}
	runtime := enrollmentRuntimeFixture()
	runtime.prepareReturned = cancel

	result := NewService(t.Context(), store, runtime).Enroll(requestCtx, EnrollmentCommand{
		ManagerURL: "https://manager.example", Token: "token-a",
	})

	if result.Status != lifecycle.StatusPending || store.enrollment.State != management.StateEnrolling {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
}

func TestServiceConfirmsRevocationAfterRemoteSuccessCancelsRequest(t *testing.T) {
	requestCtx, cancel := context.WithCancel(t.Context())
	baseStore, runtime := managedFixture()
	store := &contextCheckingStore{recordingStore: *baseStore}
	runtime.revokeReturned = cancel

	result := NewService(t.Context(), store, runtime).Unenroll(requestCtx, UnenrollmentCommand{})

	if result.Status != lifecycle.StatusApplied || store.enrollment.State != management.StateStandalone {
		t.Fatalf("result=%+v enrollment=%+v", result, store.enrollment)
	}
}

type contextCheckingStore struct {
	recordingStore
}

func (s *contextCheckingStore) Stats(ctx context.Context) (ports.EnrollmentStats, error) {
	if err := ctx.Err(); err != nil {
		return ports.EnrollmentStats{}, err
	}
	return s.recordingStore.Stats(ctx)
}

func (s *contextCheckingStore) SetEnrolling(ctx context.Context, enrollment ports.Enrollment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.recordingStore.SetEnrolling(ctx, enrollment)
}

func (s *contextCheckingStore) ConfirmEnrollmentRevocation(ctx context.Context, receipt string, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.recordingStore.ConfirmEnrollmentRevocation(ctx, receipt, revokedAt)
}

func enrollmentRuntimeFixture() *recordingRuntime {
	return &recordingRuntime{
		identity: ports.EnrollmentIdentity{TenantID: "local", AgentID: "device-a"},
		preparation: recordingPreparation{enrollment: ports.Enrollment{
			State: management.StateEnrolling, TenantID: "tenant-a", AgentID: "agent-a", ManagerURL: "https://manager.example",
		}},
	}
}

func managedFixture() (*recordingStore, *recordingRuntime) {
	store := &recordingStore{enrollment: ports.Enrollment{
		State: management.StateManaged, TenantID: "tenant-a", AgentID: "agent-a",
		EnrollmentID: "enrollment-a", CertificateSerial: "42", ManagerURL: "https://manager.example",
	}}
	runtime := &recordingRuntime{identity: ports.EnrollmentIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	return store, runtime
}
