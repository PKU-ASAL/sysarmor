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
		got.BootstrapTokenHash != want.BootstrapTokenHash || !got.BootstrapFetchedAt.Equal(want.BootstrapFetchedAt) || got.Labels["env"] != "prod" {
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
		Labels: map[string]string{"env": "prod"}, CreatedBy: "admin-a",
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
