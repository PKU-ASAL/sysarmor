package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
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
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.EnrollmentTransaction) error {
		return tx.Enrollments().Put(ctx, want)
	}); err != nil {
		t.Fatal(err)
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
	if got.ID != want.ID || got.TenantID != want.TenantID || got.AgentID != want.AgentID {
		t.Fatalf("enrollment = %#v", got)
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
	t.Helper()
	value, err := tenant.NewID("tenant-a")
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
		ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a", TokenHash: "token-hash",
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
