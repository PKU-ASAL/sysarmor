package runtime

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
)

func TestCompletionReporterRetriesReadyOutboxAfterRestart(t *testing.T) {
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
	var attempts atomic.Int32
	failing := newUnenrollmentCompletionReporter(store, func(context.Context, sqlite.UnenrollmentCompletion) error {
		attempts.Add(1)
		return errors.New("manager unavailable")
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := failing.ReportOnce(t.Context()); err == nil || sent {
		t.Fatalf("first report sent=%t err=%v", sent, err)
	}
	completion, ok, err := store.UnenrollmentCompletion(t.Context())
	if err != nil || !ok || completion.AttemptCount != 1 || completion.LastError == "" {
		t.Fatalf("completion=%+v ok=%t err=%v", completion, ok, err)
	}

	restarted := newUnenrollmentCompletionReporter(store, func(context.Context, sqlite.UnenrollmentCompletion) error {
		attempts.Add(1)
		return nil
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := restarted.ReportOnce(t.Context()); err != nil || !sent {
		t.Fatalf("restart report sent=%t err=%v", sent, err)
	}
	if _, ok, err := store.UnenrollmentCompletion(t.Context()); err != nil || ok || attempts.Load() != 2 {
		t.Fatalf("completion remains=%t attempts=%d err=%v", ok, attempts.Load(), err)
	}
}

func TestCompletionReporterRecoversReadyOutboxAfterStoreReopen(t *testing.T) {
	root := t.TempDir()
	store, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, parseEndpointPolicy(t, standaloneEndpointPolicyJSON)); err != nil {
		t.Fatal(err)
	}
	setManagedEnrollmentForTest(t, store)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := sqlite.Open(t.Context(), sqlite.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reporter := newUnenrollmentCompletionReporter(reopened, func(context.Context, sqlite.UnenrollmentCompletion) error {
		return nil
	}, time.Millisecond, 10*time.Millisecond)
	if sent, err := reporter.ReportOnce(t.Context()); err != nil || !sent {
		t.Fatalf("reopened report sent=%t err=%v", sent, err)
	}
	if _, ok, err := reopened.UnenrollmentCompletion(t.Context()); err != nil || ok {
		t.Fatalf("completion remains after reopened report: ok=%t err=%v", ok, err)
	}
}

func TestHealthReportsCompletionOutboxLifecycle(t *testing.T) {
	store := coordinatorManagedStore(t)
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	runner := newEndpointPolicyRunner(t, store, &healthOnlySensor{})
	assertManagerCompletionStatus(t, runner, "revocation_pending", "")

	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Unix(100, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCompletionAttempt(t.Context(), "manager unavailable"); err != nil {
		t.Fatal(err)
	}
	assertManagerCompletionStatus(t, runner, "endpoint_completion_pending", "manager unavailable")
}

func assertManagerCompletionStatus(t *testing.T, runner *Coordinator, wantStatus, wantError string) {
	t.Helper()
	status, err := (&runtimeHealthSource{health: runner.healthRuntime()}).Lifecycle(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status.ManagerCompletionStatus != wantStatus || status.LastError != wantError || status.UpdatedAt.IsZero() {
		t.Fatalf("management lifecycle=%+v", status)
	}
	if !status.TransitionPending && status.LastError == "" {
		t.Fatal("management lifecycle is not degraded")
	}
}
