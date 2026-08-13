package enrollment

import (
	"context"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type recordingBackend struct {
	enrollment       localstore.Enrollment
	beginCalls       int
	prepareCalls     int
	completion       localstore.UnenrollmentCompletion
	completionExists bool
}

func (b *recordingBackend) Enrollment(context.Context) (localstore.Enrollment, error) {
	return b.enrollment, nil
}

func (b *recordingBackend) Stats(context.Context) (localstore.Stats, error) {
	return localstore.Stats{}, nil
}

func (b *recordingBackend) SetEnrolling(context.Context, localstore.Enrollment) error { return nil }

func (b *recordingBackend) BeginUnenrollment(context.Context) (localstore.Enrollment, error) {
	b.beginCalls++
	b.enrollment.State = localstore.StateUnenrolling
	return b.enrollment, nil
}

func (b *recordingBackend) PrepareUnenrollment(context.Context, string, string) (localstore.Enrollment, error) {
	b.prepareCalls++
	b.enrollment.State = localstore.StateUnenrolling
	return b.enrollment, nil
}

func (b *recordingBackend) UnenrollmentCompletion(context.Context) (localstore.UnenrollmentCompletion, bool, error) {
	return b.completion, b.completionExists, nil
}

func (b *recordingBackend) RecordUnenrollmentError(context.Context, string) error { return nil }

func (b *recordingBackend) ConfirmEnrollmentRevocation(context.Context, string, time.Time) error {
	return nil
}

func TestEnrollmentMappingPreservesWorkflowState(t *testing.T) {
	revokedAt := time.Unix(42, 0).UTC()
	want := ports.Enrollment{
		State: management.StateUnenrolling, TenantID: "tenant-a", AgentID: "agent-a",
		EnrollmentID: "enrollment-a", CertificateSerial: "17", ManagerURL: "https://manager.example",
		GatewayAddress: "gateway:443", TLSCAPath: "ca", TLSCertPath: "cert",
		TLSKeyPath: "key", TLSServerName: "gateway",
		UploadHistory: true, ManagedFromSequence: 9, RevocationConfirmed: true,
		RevokedAt: revokedAt, RevocationReceipt: "receipt-a",
	}

	if got := fromLocalEnrollment(toLocalEnrollment(want)); got != want {
		t.Fatalf("round trip=%+v want=%+v", got, want)
	}
}

func TestCompletionMappingKeepsDurableOutboxToken(t *testing.T) {
	local := localstore.UnenrollmentCompletion{
		Token: "completion-token", TokenHash: "completion-hash", Status: localstore.CompletionPrepared,
	}
	got := fromLocalCompletion(local)
	if got.Token != local.Token || got.TokenHash != local.TokenHash || got.Status != ports.CompletionPrepared {
		t.Fatalf("completion=%+v", got)
	}
}

func TestPrepareUnenrollmentHidesLegacyProtocolFromApplication(t *testing.T) {
	backend := &recordingBackend{enrollment: localstore.Enrollment{
		State: localstore.StateManaged, UnenrollmentProtocol: localstore.UnenrollmentProtocolLegacyMTLS,
	}}
	store := NewStore(backend, func(context.Context, string) error { return nil })

	_, completion, err := store.PrepareUnenrollment(t.Context(), "token", "hash")
	if err != nil || backend.beginCalls != 1 || backend.prepareCalls != 0 || completion.TokenHash != "" {
		t.Fatalf("completion=%+v backend=%+v err=%v", completion, backend, err)
	}
}
