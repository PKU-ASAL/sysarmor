package response

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestResponseRepositoryRoundTripsCommandAndAcknowledgement(t *testing.T) {
	db := newResponseTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterResponse(t)
	createResponse(t, uow, current)
	acknowledged, err := current.Acknowledge(domainresponse.Acknowledgement{
		TenantID: current.TenantID, AgentID: current.AgentID, Accepted: true, Executed: true, Message: "done",
	}, time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		return tx.Responses().Put(ctx, current, acknowledged.Command)
	}); err != nil {
		t.Fatal(err)
	}

	got := getResponse(t, uow, current.TenantID, current.ID)
	if got.Status != domainresponse.StatusAcknowledged || got.Ack == nil || got.Ack.Message != "done" || !got.Ack.Executed {
		t.Fatalf("response = %+v ack=%+v", got, got.Ack)
	}
}

func TestResponseRepositoryRejectsUpdateFromStaleDocument(t *testing.T) {
	db := newResponseTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterResponse(t)
	createResponse(t, uow, current)
	first, err := current.Decide(domainresponse.Approval{Actor: "admin-a", Role: "admin", Approved: true}, current.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := current.Decide(domainresponse.Approval{Actor: "admin-b", Role: "admin", Approved: true}, current.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		return tx.Responses().Put(ctx, current, first)
	}); err != nil {
		t.Fatal(err)
	}
	err = uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		return tx.Responses().Put(ctx, current, second)
	})
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

func TestResponseUnitOfWorkRollsBackCommandAndAudit(t *testing.T) {
	db := newResponseTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterResponse(t)
	wantErr := errors.New("stop transaction")
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		if _, err := tx.Responses().Create(ctx, current); err != nil {
			return err
		}
		if err := tx.Audits().Append(ctx, domainresponse.AuditRecord{
			ID: "audit-a", TenantID: current.TenantID, ResponseID: current.ID,
			Action: "create", Status: current.Status, OccurredAt: current.CreatedAt,
		}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error=%v", err)
	}
	assertResponseRows(t, db, "response_audit", 0)
	assertResponseRows(t, db, "response_decisions", 0)
}

func newResponseTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`CREATE TABLE response_audit (tenant_id TEXT, response_id TEXT, agent_id TEXT, status TEXT, action TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, command BLOB, ack BLOB, PRIMARY KEY (tenant_id,response_id))`,
		`CREATE TABLE response_decisions (tenant_id TEXT, audit_id TEXT, response_id TEXT, action TEXT, actor TEXT, role TEXT, approved BOOLEAN, reason TEXT, status TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id,audit_id))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func adapterResponse(t *testing.T) domainresponse.Command {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domainresponse.NewCommand(domainresponse.Command{
		ID: "response-a", TenantID: tenantID, AgentID: "agent-a", Action: "collect",
		ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"admin"},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func createResponse(t *testing.T, uow *UnitOfWork, value domainresponse.Command) {
	t.Helper()
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		_, err := tx.Responses().Create(ctx, value)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func getResponse(t *testing.T, uow *UnitOfWork, tenantID tenant.ID, id string) domainresponse.Command {
	t.Helper()
	var value domainresponse.Command
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ResponseTransaction) error {
		var err error
		value, err = tx.Responses().Get(ctx, tenantID, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertResponseRows(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s rows=%d want=%d", table, got, want)
	}
}
