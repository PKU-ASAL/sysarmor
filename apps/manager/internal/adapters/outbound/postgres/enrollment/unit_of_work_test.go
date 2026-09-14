package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestEnrollmentUnitOfWorkRollsBackEnrollmentAndCertificate(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	value := adapterEnrollment(t)
	certificate := domainenrollment.Certificate{
		TenantID: value.TenantID, AgentID: value.AgentID, EnrollmentID: value.ID,
		SerialNumber: "42", CreatedAt: time.Unix(100, 0).UTC(),
	}

	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		if err := tx.Enrollments().Put(ctx, value); err != nil {
			return err
		}
		if err := tx.Certificates().Put(ctx, certificate); err != nil {
			return err
		}
		return errors.New("stop transaction")
	})
	if err == nil {
		t.Fatal("failed transaction committed")
	}
	assertEnrollmentRows(t, db, "enrollments", 0)
	assertEnrollmentRows(t, db, "agent_certificates", 0)
}

func TestEnrollmentRepositoryReadsTokenIdentity(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	want := adapterEnrollment(t)
	want.BootstrapFetchedAt = time.Unix(75, 0).UTC()
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		return tx.Enrollments().Put(ctx, want)
	}); err != nil {
		t.Fatal(err)
	}
	var hostID string
	if err := db.QueryRow(`SELECT host_id FROM enrollments WHERE tenant_id=? AND enrollment_id=?`,
		want.TenantID.String(), want.ID).Scan(&hostID); err != nil || hostID != want.HostID {
		t.Fatalf("host_id column = %q error=%v", hostID, err)
	}

	var got domainenrollment.Enrollment
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		got, err = tx.Enrollments().ByTokenHash(ctx, "token-hash")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.TenantID != want.TenantID || got.AgentID != want.AgentID ||
		got.HostID != want.HostID || got.GatewayAddress != want.GatewayAddress || got.Profile != want.Profile ||
		got.BootstrapTokenHash != want.BootstrapTokenHash || !got.BootstrapFetchedAt.Equal(want.BootstrapFetchedAt) ||
		got.Channel != want.Channel || got.ArtifactID != want.ArtifactID || got.ArtifactSHA256 != want.ArtifactSHA256 ||
		got.ArtifactURL != want.ArtifactURL || got.Labels["env"] != "prod" {
		t.Fatalf("enrollment = %#v", got)
	}
}

func TestEnrollmentRepositoryReadsBootstrapIdentity(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	want := adapterEnrollment(t)
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		return tx.Enrollments().Put(ctx, want)
	}); err != nil {
		t.Fatal(err)
	}
	var got domainenrollment.Enrollment
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		got, err = tx.Enrollments().ByBootstrapTokenHash(ctx, "bootstrap-hash")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.BootstrapTokenHash != want.BootstrapTokenHash {
		t.Fatalf("enrollment = %#v", got)
	}
}

func TestEnrollmentRepositoryRejectsStaleBootstrapRedemption(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterEnrollment(t)
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		return tx.Enrollments().Put(ctx, current)
	}); err != nil {
		t.Fatal(err)
	}
	first, err := current.RedeemBootstrap("bootstrap-hash", "rotated-a", "enr_...aaa", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, err := current.RedeemBootstrap("bootstrap-hash", "rotated-b", "enr_...bbb", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	err = uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		if err := tx.Enrollments().RedeemBootstrap(ctx, current, first); err != nil {
			return err
		}
		return tx.Enrollments().RedeemBootstrap(ctx, current, second)
	})
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("stale redemption kind = %v error=%v", failure.KindOf(err), err)
	}
}

func TestEnrollmentRepositoryListsTenantAndStatus(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	issued := adapterEnrollment(t)
	issued.Status = domainenrollment.StatusIssued
	active := adapterEnrollment(t)
	active.ID, active.TokenHash = "enroll-active", "token-active"
	other := issued
	other.ID, other.TenantID, other.TokenHash = "enroll-other", mustAdapterTenantID(t, "tenant-b"), "token-other"
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		for _, value := range []domainenrollment.Enrollment{active, issued, other} {
			if err := tx.Enrollments().Put(ctx, value); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var values []domainenrollment.Enrollment
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		values, err = tx.Enrollments().List(ctx, mustAdapterTenant(t), domainenrollment.StatusIssued)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ID != issued.ID {
		t.Fatalf("enrollments = %#v", values)
	}
}

func TestUnenrollmentRepositoryRoundTripsBoundIdentity(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	identity := domainenrollment.UnenrollmentIdentity{TenantID: mustAdapterTenant(t), AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42"}
	want, err := domainenrollment.NewPendingUnenrollment(identity, "receipt-a", "token-hash", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		return tx.Unenrollments().Put(ctx, want)
	}); err != nil {
		t.Fatal(err)
	}
	var got domainenrollment.Unenrollment
	err = uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		got, err = tx.Unenrollments().Get(ctx, identity.TenantID, identity.EnrollmentID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != identity || got.Receipt != want.Receipt || got.CompletionTokenHash != want.CompletionTokenHash {
		t.Fatalf("unenrollment = %#v", got)
	}
}

func TestUnenrollmentRepositoryListsTenant(t *testing.T) {
	db := newEnrollmentTestDB(t)
	uow := NewUnitOfWork(db)
	want := pendingAdapterUnenrollment(t, "tenant-a", "enroll-a")
	other := pendingAdapterUnenrollment(t, "tenant-b", "enroll-b")
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		if err := tx.Unenrollments().Put(ctx, want); err != nil {
			return err
		}
		return tx.Unenrollments().Put(ctx, other)
	}); err != nil {
		t.Fatal(err)
	}
	var values []domainenrollment.Unenrollment
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		values, err = tx.Unenrollments().List(ctx, mustAdapterTenant(t))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].Identity != want.Identity {
		t.Fatalf("unenrollments = %#v", values)
	}
}

func TestInstallMaterialRepositoryResolvesActiveChannel(t *testing.T) {
	db := newEnrollmentTestDB(t)
	if _, err := db.Exec(`INSERT INTO artifacts
(tenant_id,artifact_id,sha256,status,storage_path,data) VALUES (?,?,?,?,?,?)`, "tenant-a", "artifact-a", "sha256-a", "active", "/artifacts/agent.tar.gz",
		[]byte(`{"artifact_id":"artifact-a","sha256":"sha256-a","status":"active","metadata":{"download_url":"https://packages.example/agent.tar.gz"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO artifact_channels (tenant_id,channel_name,artifact_id,data) VALUES (?,?,?,?)`,
		"tenant-a", "linux-systemd-stable", "artifact-a", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	var material domainenrollment.InstallMaterial
	err := NewUnitOfWork(db).Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		material, err = tx.InstallMaterials().Resolve(ctx, mustAdapterTenant(t), "linux-systemd-stable", "ignored")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if material.Channel != "linux-systemd-stable" || material.ArtifactID != "artifact-a" ||
		material.ArtifactSHA256 != "sha256-a" || material.ArtifactURL != "https://packages.example/agent.tar.gz" {
		t.Fatalf("material = %#v", material)
	}
	var artifact domainenrollment.InstallArtifact
	err = NewUnitOfWork(db).Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		artifact, err = tx.InstallMaterials().GetArtifact(ctx, mustAdapterTenant(t), "artifact-a")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ID != "artifact-a" || artifact.SHA256 != "sha256-a" || artifact.Status != "active" ||
		artifact.StoragePath != "/artifacts/agent.tar.gz" || artifact.DownloadURL != "https://packages.example/agent.tar.gz" {
		t.Fatalf("artifact = %#v", artifact)
	}
}

func TestInstallMaterialRepositoryListsTenantAgentArtifacts(t *testing.T) {
	db := newEnrollmentTestDB(t)
	for _, row := range []struct{ tenantID, artifactID, kind string }{
		{"tenant-a", "artifact-a", "agent"}, {"tenant-a", "policy-a", "policy"}, {"tenant-b", "artifact-b", "agent"},
	} {
		raw := []byte(`{"artifact_id":"` + row.artifactID + `","version":"1.0.0","os":"linux","arch":"amd64","sha256":"sha256-a","status":"active","created_at":"1970-01-01T00:01:40Z","metadata":{"download_url":"https://packages.example/` + row.artifactID + `.tar.gz"}}`)
		if _, err := db.Exec(`INSERT INTO artifacts
(tenant_id,artifact_id,artifact_kind,sha256,status,storage_path,created_at,data) VALUES (?,?,?,?,?,?,?,?)`,
			row.tenantID, row.artifactID, row.kind, "sha256-a", "active", "", time.Unix(100, 0).UTC(), raw); err != nil {
			t.Fatal(err)
		}
	}
	var artifacts []domainenrollment.DeploymentArtifact
	err := NewUnitOfWork(db).Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		var err error
		artifacts, err = tx.InstallMaterials().ListArtifacts(ctx, mustAdapterTenant(t))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].ID != "artifact-a" ||
		artifacts[0].DownloadURL != "https://packages.example/artifact-a.tar.gz" {
		t.Fatalf("artifacts = %#v", artifacts)
	}
}

func newEnrollmentTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE enrollments (tenant_id TEXT, enrollment_id TEXT, agent_id TEXT, host_id TEXT, token_hash TEXT, status TEXT, created_at TIMESTAMP, expires_at TIMESTAMP, used_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,enrollment_id))`,
		`CREATE TABLE agent_certificates (tenant_id TEXT, agent_id TEXT, serial_number TEXT, enrollment_id TEXT, not_before TIMESTAMP, not_after TIMESTAMP, created_at TIMESTAMP, revoked_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,serial_number))`,
		`CREATE TABLE agent_unenrollments (tenant_id TEXT, enrollment_id TEXT, agent_id TEXT, certificate_serial TEXT, status TEXT, revoked_at TIMESTAMP, endpoint_completed_at TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,enrollment_id))`,
		`CREATE TABLE artifacts (tenant_id TEXT, artifact_id TEXT, artifact_kind TEXT, sha256 TEXT, status TEXT, storage_path TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,artifact_id))`,
		`CREATE TABLE artifact_channels (tenant_id TEXT, channel_name TEXT, artifact_id TEXT, data BLOB, PRIMARY KEY (tenant_id,channel_name))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func mustAdapterTenant(t *testing.T) tenant.ID {
	return mustAdapterTenantID(t, "tenant-a")
}

func mustAdapterTenantID(t *testing.T, raw string) tenant.ID {
	t.Helper()
	value, err := tenant.NewID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func pendingAdapterUnenrollment(t *testing.T, tenantID, enrollmentID string) domainenrollment.Unenrollment {
	t.Helper()
	value, err := domainenrollment.NewPendingUnenrollment(domainenrollment.UnenrollmentIdentity{
		TenantID: mustAdapterTenantID(t, tenantID), AgentID: "agent-a", EnrollmentID: enrollmentID, CertificateSerial: "42",
	}, "receipt-a", "token-hash", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func adapterEnrollment(t *testing.T) domainenrollment.Enrollment {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domainenrollment.NewEnrollment(domainenrollment.Enrollment{
		ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a", HostID: "host-a", TokenHash: "token-hash",
		TokenPreview: "token...hash", BootstrapTokenHash: "bootstrap-hash", BootstrapTokenPreview: "boot...hash",
		GatewayAddress: "gateway:9444", GatewayServerName: "gateway.internal", Profile: "linux-systemd",
		Channel: "linux-systemd-stable", ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a",
		ArtifactURL: "https://packages.example/agent.tar.gz",
		Labels:      map[string]string{"env": "prod"}, CreatedBy: "admin-a",
		Status: domainenrollment.StatusActive, CreatedAt: time.Unix(50, 0).UTC(), ExpiresAt: time.Unix(500, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertEnrollmentRows(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}
