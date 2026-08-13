package control

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"

	_ "modernc.org/sqlite"
)

func TestRevocationRepositoryIsIdempotent(t *testing.T) {
	db := newRevocationTestDB(t)
	insertCertificate(t, db, "legacy_mtls")
	repository := NewRevocationRepository(db)
	request := domaingateway.RevokeEnrollment{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42"}
	first, err := repository.Revoke(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.Revoke(context.Background(), request)
	if err != nil || first.ReceiptID == "" || first.ReceiptID != second.ReceiptID || !first.RevokedAt.Equal(second.RevokedAt) {
		t.Fatalf("first = %+v, second = %+v, err = %v", first, second, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM agent_unenrollments WHERE tenant_id='tenant-a' AND enrollment_id='enroll-a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("unenrollments = %d, err = %v", count, err)
	}
}

func TestRevocationRepositoryPersistsCompletionBinding(t *testing.T) {
	db := newRevocationTestDB(t)
	insertCertificate(t, db, "completion_v1")
	repository := NewRevocationRepository(db)
	request := domaingateway.RevokeEnrollment{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42", CompletionTokenHash: strings.Repeat("a", 64)}
	result, err := repository.Revoke(context.Background(), request)
	if err != nil || !result.CompletionRequired {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM agent_unenrollments WHERE tenant_id='tenant-a' AND enrollment_id='enroll-a'`).Scan(&status); err != nil || status != "revoked_endpoint_pending" {
		t.Fatalf("status = %q, err = %v", status, err)
	}
}

func newRevocationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`CREATE TABLE agent_certificates (tenant_id TEXT, agent_id TEXT, serial_number TEXT, enrollment_id TEXT, revoked_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, serial_number))`,
		`CREATE TABLE agent_unenrollments (tenant_id TEXT, enrollment_id TEXT, agent_id TEXT, certificate_serial TEXT, status TEXT, revoked_at TIMESTAMP, endpoint_completed_at TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, enrollment_id))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func insertCertificate(t *testing.T, db *sql.DB, protocol string) {
	t.Helper()
	document := `{"tenant_id":"tenant-a","agent_id":"agent-a","enrollment_id":"enroll-a","serial_number":"42","unenrollment_protocol":"` + protocol + `"}`
	if _, err := db.Exec(`INSERT INTO agent_certificates VALUES ('tenant-a','agent-a','42','enroll-a',NULL,?)`, []byte(document)); err != nil {
		t.Fatal(err)
	}
}
