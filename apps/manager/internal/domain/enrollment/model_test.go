package enrollment

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestEnrollmentConsumesTokenOnce(t *testing.T) {
	enrollment := newActiveEnrollment(t)
	usedAt := time.Unix(100, 0).UTC()

	used, err := enrollment.Consume(usedAt)
	if err != nil {
		t.Fatal(err)
	}
	if used.Status != StatusUsed || !used.UsedAt.Equal(usedAt) {
		t.Fatalf("used enrollment = %#v", used)
	}
	if enrollment.Status != StatusActive || !enrollment.UsedAt.IsZero() {
		t.Fatalf("original enrollment mutated = %#v", enrollment)
	}
	if _, err := used.Consume(usedAt); failure.KindOf(err) != failure.Conflict {
		t.Fatalf("second consume kind = %v", failure.KindOf(err))
	}
}

func TestUnenrollmentRejectsIdentityMismatch(t *testing.T) {
	record, err := NewPendingUnenrollment(UnenrollmentIdentity{
		TenantID:          mustTenantID(t, "tenant-a"),
		AgentID:           "agent-a",
		EnrollmentID:      "enroll-a",
		CertificateSerial: "42",
	}, "receipt-a", "token-hash", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}

	_, err = record.Complete(UnenrollmentCompletion{
		Identity: UnenrollmentIdentity{
			TenantID:          mustTenantID(t, "tenant-a"),
			AgentID:           "other-agent",
			EnrollmentID:      "enroll-a",
			CertificateSerial: "42",
		},
		Receipt:   "receipt-a",
		TokenHash: "token-hash",
	}, time.Unix(200, 0).UTC())
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("identity mismatch kind = %v", failure.KindOf(err))
	}
}

func newActiveEnrollment(t *testing.T) Enrollment {
	t.Helper()
	value, err := NewEnrollment(Enrollment{
		ID:        "enroll-a",
		TenantID:  mustTenantID(t, "tenant-a"),
		TokenHash: "token-hash",
		Status:    StatusActive,
		CreatedAt: time.Unix(50, 0).UTC(),
		ExpiresAt: time.Unix(500, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustTenantID(t *testing.T, raw string) tenant.ID {
	t.Helper()
	value, err := tenant.NewID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
