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

func TestLegacyUnenrollmentAllowsMissingCompletionToken(t *testing.T) {
	record, err := NewLegacyUnenrollment(UnenrollmentIdentity{
		TenantID:          mustTenantID(t, "tenant-a"),
		AgentID:           "agent-a",
		EnrollmentID:      "enroll-a",
		CertificateSerial: "42",
	}, "receipt-a", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != UnenrollmentLegacy || record.CompletionTokenHash != "" {
		t.Fatalf("legacy unenrollment = %#v", record)
	}
}

func TestEnrollmentIssueReplaysOriginalCertificateForSameKey(t *testing.T) {
	value := newActiveEnrollment(t)
	first := Issuance{KeySHA256: "key-a", Certificate: Certificate{SerialNumber: "42", CertificatePEM: "first"}}
	issued, _, err := value.Issue(first, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	retry := Issuance{KeySHA256: "key-a", Certificate: Certificate{SerialNumber: "99", CertificatePEM: "rotated"}}
	replayed, certificate, err := issued.Issue(retry, time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Issuance.Certificate.SerialNumber != "42" || certificate.CertificatePEM != "first" {
		t.Fatalf("replay changed certificate: enrollment=%#v certificate=%#v", replayed, certificate)
	}
}

func TestEnrollmentRedeemsBootstrapOnceAndRotatesToken(t *testing.T) {
	value := newActiveEnrollment(t)
	value.BootstrapTokenHash = "bootstrap-hash"
	redeemedAt := time.Unix(100, 0).UTC()

	redeemed, err := value.RedeemBootstrap("bootstrap-hash", "rotated-hash", "enr_...ated", redeemedAt)
	if err != nil {
		t.Fatal(err)
	}
	if redeemed.TokenHash != "rotated-hash" || redeemed.TokenPreview != "enr_...ated" ||
		!redeemed.BootstrapFetchedAt.Equal(redeemedAt) {
		t.Fatalf("redeemed enrollment = %#v", redeemed)
	}
	if redeemed.BootstrapTokenHash != "" || redeemed.BootstrapTokenPreview != "" {
		t.Fatalf("bootstrap secret was retained = %#v", redeemed)
	}
	if _, err := redeemed.RedeemBootstrap("bootstrap-hash", "other-hash", "enr_...ther", redeemedAt); failure.KindOf(err) != failure.Conflict {
		t.Fatalf("second redemption kind = %v", failure.KindOf(err))
	}
}

func TestValidateIdentityRejectsPathComponents(t *testing.T) {
	for _, values := range [][2]string{{"tenant/a", "agent-a"}, {"tenant-a", "../agent"}, {"tenant-a", "agent?admin=true"}} {
		if err := ValidateIdentity(values[0], values[1]); failure.KindOf(err) != failure.InvalidArgument {
			t.Fatalf("identity=%q/%q kind=%v", values[0], values[1], failure.KindOf(err))
		}
	}
}

func TestValidateGatewayAcceptsHostAndBracketedIPv6(t *testing.T) {
	for _, address := range []string{"gateway.example:9444", "[::1]:9444"} {
		if err := ValidateGateway(address, "gateway.example"); err != nil {
			t.Fatalf("gateway=%q error=%v", address, err)
		}
	}
}

func TestNewEnrollmentPreservesInstallMaterial(t *testing.T) {
	value := newActiveEnrollment(t)
	value.Channel = "linux-systemd-stable"
	value.ArtifactID = "artifact-a"
	value.ArtifactSHA256 = "sha256-a"
	value.ArtifactURL = "https://packages.example/agent.tar.gz"

	created, err := NewEnrollment(value)
	if err != nil {
		t.Fatal(err)
	}
	if created.Channel != value.Channel || created.ArtifactID != value.ArtifactID ||
		created.ArtifactSHA256 != value.ArtifactSHA256 || created.ArtifactURL != value.ArtifactURL {
		t.Fatalf("install material = %#v", created)
	}
}

func TestEnrollmentAuthorizesBoundArtifactBeforeExpiry(t *testing.T) {
	value := newActiveEnrollment(t)
	value.ArtifactID = "artifact-a"

	artifactID, err := value.AuthorizeArtifact(time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if artifactID != "artifact-a" {
		t.Fatalf("artifact ID = %q", artifactID)
	}
	if _, err := value.AuthorizeArtifact(time.Unix(600, 0).UTC()); failure.KindOf(err) != failure.FailedPrecondition {
		t.Fatalf("expired artifact kind = %v", failure.KindOf(err))
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
