package control

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestControlUnitOfWorkRollsBackCommandAndAudit(t *testing.T) {
	db := newControlApplicationTestDB(t)
	uow := NewUnitOfWork(db)
	command := adapterCommand(t)
	wantErr := errors.New("stop transaction")

	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		if _, err := tx.Commands().Create(ctx, command); err != nil {
			return err
		}
		if err := tx.Audits().Append(ctx, domaincontrol.AuditRecord{
			ID: "audit-a", TenantID: command.TenantID, ResourceID: command.ID,
			Action: "create", Status: string(command.Status), OccurredAt: command.CreatedAt,
		}); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("transaction error = %v", err)
	}
	assertControlRows(t, db, "control_commands", 0)
	assertControlRows(t, db, "control_audit", 0)
}

func TestControlRepositoryRoundTripsCommand(t *testing.T) {
	db := newControlApplicationTestDB(t)
	want := adapterCommand(t)
	uow := NewUnitOfWork(db)
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		_, err := tx.Commands().Create(ctx, want)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	var got domaincontrol.Command
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		var err error
		got, err = tx.Commands().Get(ctx, want.TenantID, want.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.TenantID != want.TenantID || got.AgentID != want.AgentID ||
		got.Type != want.Type || got.ContentRef != want.ContentRef || string(got.Payload) != string(want.Payload) ||
		got.Status != want.Status || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("command = %+v", got)
	}
}

func TestControlRepositoryRejectsCommandUpdateFromStaleVersion(t *testing.T) {
	db := newControlApplicationTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterCommand(t)
	createControlCommand(t, uow, current)
	first := current.MarkSent(current.UpdatedAt)
	second := current.Cancel("admin", "cancel", current.UpdatedAt)

	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		return tx.Commands().Put(ctx, current, first)
	}); err != nil {
		t.Fatal(err)
	}
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		return tx.Commands().Put(ctx, current, second)
	})
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v error=%v", failure.KindOf(err), err)
	}
}

func TestControlRepositoryRejectsEvidenceUpdateFromStaleVersion(t *testing.T) {
	db := newControlApplicationTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterEvidence(t)
	createEvidence(t, uow, current)
	first, err := current.Complete(domaincontrol.EvidenceResult{
		TenantID: current.TenantID, AgentID: current.AgentID, OK: true, Evidence: []byte(`{"result":"first"}`),
	}, current.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	second, err := current.Complete(domaincontrol.EvidenceResult{
		TenantID: current.TenantID, AgentID: current.AgentID, OK: true, Evidence: []byte(`{"result":"second"}`),
	}, current.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}

	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		return tx.Evidence().Put(ctx, current, first)
	}); err != nil {
		t.Fatal(err)
	}
	err = uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		return tx.Evidence().Put(ctx, current, second)
	})
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v error=%v", failure.KindOf(err), err)
	}
}

func TestControlUnitOfWorkRollsBackCommandWhenAuditIDConflicts(t *testing.T) {
	db := newControlApplicationTestDB(t)
	uow := NewUnitOfWork(db)
	current := adapterCommand(t)
	createControlCommand(t, uow, current)
	audit := domaincontrol.AuditRecord{
		ID: "audit-a", TenantID: current.TenantID, ResourceID: current.ID,
		Action: "create", Status: string(current.Status), OccurredAt: current.CreatedAt,
	}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		return tx.Audits().Append(ctx, audit)
	}); err != nil {
		t.Fatal(err)
	}

	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		next := current.MarkSent(current.UpdatedAt.Add(time.Second))
		if err := tx.Commands().Put(ctx, current, next); err != nil {
			return err
		}
		return tx.Audits().Append(ctx, audit)
	})
	if err == nil {
		t.Fatal("duplicate audit ID committed command update")
	}
	got := getControlCommand(t, uow, current.TenantID, current.ID)
	if got.Status != domaincontrol.CommandPending || got.AttemptCount != 0 {
		t.Fatalf("command escaped rolled back transaction: %+v", got)
	}
}

func newControlApplicationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`CREATE TABLE control_commands (tenant_id TEXT, command_id TEXT, agent_id TEXT, command_type TEXT, status TEXT, policy_id TEXT, policy_version INTEGER, content_ref TEXT, content_kind TEXT, content_version TEXT, actor TEXT, reason TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, sent_at TIMESTAMP, last_sent_at TIMESTAMP, acked_at TIMESTAMP, canceled_at TIMESTAMP, expired_at TIMESTAMP, attempt_count INTEGER, data BLOB, PRIMARY KEY (tenant_id, command_id))`,
		`CREATE TABLE evidence_pullbacks (tenant_id TEXT, request_id TEXT, agent_id TEXT, incident_id TEXT, status TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, request_id))`,
		`CREATE TABLE control_audit (tenant_id TEXT, audit_id TEXT, resource_id TEXT, action TEXT, actor TEXT, reason TEXT, status TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, audit_id))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func adapterCommand(t *testing.T) domaincontrol.Command {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domaincontrol.NewCommand(domaincontrol.Command{
		ID: "command-a", TenantID: tenantID, AgentID: "agent-a",
		Type: domaincontrol.CommandTypeContentUpdate, ContentRef: "ioc:test",
		ContentKind: "iocpack", ContentVersion: "v1", Payload: []byte(`{"kind":"iocpack"}`),
		Actor: "operator", Reason: "refresh",
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func adapterEvidence(t *testing.T) domaincontrol.EvidencePullback {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domaincontrol.NewEvidencePullback(domaincontrol.EvidencePullback{
		ID: "evidence-a", TenantID: tenantID, AgentID: "agent-a",
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func createControlCommand(t *testing.T, uow *UnitOfWork, value domaincontrol.Command) {
	t.Helper()
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		_, err := tx.Commands().Create(ctx, value)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func createEvidence(t *testing.T, uow *UnitOfWork, value domaincontrol.EvidencePullback) {
	t.Helper()
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		_, err := tx.Evidence().Create(ctx, value)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func getControlCommand(t *testing.T, uow *UnitOfWork, tenantID tenant.ID, id string) domaincontrol.Command {
	t.Helper()
	var value domaincontrol.Command
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.ControlTransaction) error {
		var err error
		value, err = tx.Commands().Get(ctx, tenantID, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertControlRows(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}
