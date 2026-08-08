package policy

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestPolicyRepositoryIsTenantScoped(t *testing.T) {
	db := newPolicyTestDB(t)
	insertPolicyDocument(t, db, "tenant-a", "policy-a", 1, `{"tenant_id":"tenant-a","policy_id":"policy-a","version":1}`)
	insertPolicyDocument(t, db, "tenant-b", "policy-a", 1, `{"tenant_id":"tenant-b","policy_id":"policy-a","version":1}`)
	uow := NewUnitOfWork(db)
	tenantA := mustAdapterTenantID(t, "tenant-a")

	var got domainpolicy.Policy
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		var err error
		got, err = tx.Policies().Get(ctx, tenantA, "policy-a", 1)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != tenantA || string(got.Document) == "" {
		t.Fatalf("Get() = %+v", got)
	}
}

func TestPolicyUnitOfWorkRollsBackAllWrites(t *testing.T) {
	db := newPolicyTestDB(t)
	uow := NewUnitOfWork(db)
	tenantID := mustAdapterTenantID(t, "tenant-a")

	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		if err := tx.Assignments().Put(ctx, domainpolicy.Assignment{
			ID: "assignment-a", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"},
			PolicyID: "policy-a", PolicyVersion: 1,
		}); err != nil {
			return err
		}
		if err := tx.Audits().Append(ctx, tenantID, audit.Record{
			ID: "audit-a", TenantID: tenantID, Action: "policy.assign", PolicyID: "policy-a",
		}); err != nil {
			return err
		}
		return errors.New("stop transaction")
	})
	if err == nil {
		t.Fatal("Execute() committed failed transaction")
	}
	assertRowCount(t, db, "policy_assignments", 0)
	assertRowCount(t, db, "policy_audit", 0)
}

func newPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE policies (tenant_id TEXT, policy_id TEXT, version INTEGER, scope_type TEXT, scope_selector TEXT, mode TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, policy_id, version))`,
		`CREATE TABLE policy_assignments (tenant_id TEXT, assignment_id TEXT, agent_id TEXT, scope_type TEXT, scope_selector TEXT, policy_id TEXT, policy_version INTEGER, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, assignment_id))`,
		`CREATE TABLE policy_audit (tenant_id TEXT, audit_id TEXT, action TEXT, policy_id TEXT, policy_version INTEGER, assignment_id TEXT, actor TEXT, status TEXT, reason TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, audit_id))`,
		`CREATE TABLE control_commands (tenant_id TEXT, command_id TEXT, agent_id TEXT, command_type TEXT, status TEXT, policy_id TEXT, policy_version INTEGER, actor TEXT, reason TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, command_id))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func insertPolicyDocument(t *testing.T, db *sql.DB, tenantID, policyID string, version uint64, document string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO policies (tenant_id, policy_id, version, data) VALUES (?, ?, ?, ?)`, tenantID, policyID, version, []byte(document)); err != nil {
		t.Fatal(err)
	}
}

func mustAdapterTenantID(t *testing.T, value string) tenant.ID {
	t.Helper()
	id, err := tenant.NewID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertRowCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s row count = %d, want %d", table, got, want)
	}
}
