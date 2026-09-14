package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	_ "modernc.org/sqlite"
)

func TestPolicyRepositoryIsTenantScoped(t *testing.T) {
	db := newPolicyTestDB(t)
	insertPolicyDocument(t, db, "tenant-a", "policy-a", 1, ruleOnlyPolicyDocument("tenant-a", "policy-a", 1))
	insertPolicyDocument(t, db, "tenant-b", "policy-a", 1, ruleOnlyPolicyDocument("tenant-b", "policy-a", 1))
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

func TestRuleRepositoryRejectsInvalidDocument(t *testing.T) {
	db := newPolicyTestDB(t)
	if _, err := db.Exec(`INSERT INTO rules (tenant_id, rule_id, version, rule_where, data) VALUES (?, ?, ?, ?, ?)`,
		"tenant-a", "rule-a", 1, "cloud", []byte(`{"rule_id":`)); err != nil {
		t.Fatal(err)
	}
	tenantID := mustAdapterTenantID(t, "tenant-a")
	err := NewUnitOfWork(db).Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		_, err := tx.Rules().List(ctx, tenantID, domainpolicy.RuleFilter{Where: "cloud"})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "decode rule") {
		t.Fatalf("error=%v", err)
	}
}

func TestPolicyRepositoryCanonicalizesDocumentIdentity(t *testing.T) {
	db := newPolicyTestDB(t)
	insertPolicyDocument(t, db, "tenant-a", "policy-a", 2, `{
		"tenant_id":"tenant-b","policy_id":"other","version":99,"protection_mode":"rule-only",
		"collection":{},"detection":{"rulesets":[{"ref":"ruleset:a"}]},"telemetry":{},"response_policy":{}
	}`)
	uow := NewUnitOfWork(db)
	tenantA := mustAdapterTenantID(t, "tenant-a")

	var got domainpolicy.Policy
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		var err error
		got, err = tx.Policies().Get(ctx, tenantA, "policy-a", 2)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"tenant_id":"tenant-a"`, `"policy_id":"policy-a"`, `"version":2`} {
		if !strings.Contains(string(got.Document), want) {
			t.Fatalf("canonical document %s missing %s", got.Document, want)
		}
	}
}

func TestPublishedPolicyEnqueuesSnapshotInSameTransaction(t *testing.T) {
	db := newPolicyTestDB(t)
	tenantID := mustAdapterTenantID(t, "tenant-a")
	value := domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 2, Published: true, Document: []byte(ruleOnlyPolicyDocument("tenant-a", "policy-a", 2))}
	err := NewUnitOfWork(db).Execute(t.Context(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		return tx.Policies().Put(ctx, value)
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRowCount(t, db, "policy_snapshot_outbox", 1)
}

func TestPolicyRepositoryBuildsEndpointDownlinkDocument(t *testing.T) {
	db := newPolicyTestDB(t)
	insertPolicyDocument(t, db, "tenant-a", "policy-a", 2, `{
		"tenant_id":"tenant-a","policy_id":"policy-a","version":2,
		"protection_mode":"rule-only",
		"collection":{"behaviors":["process.exec"]},
		"detection":{"policy_id":"detect-a","version":1,"rulesets":[{"ref":"ruleset:a"}]},
		"telemetry":{"max_batch_items":64},
		"response_policy":{"allowed_actions":["collect"]}
	}`)
	uow := NewUnitOfWork(db)
	tenantA := mustAdapterTenantID(t, "tenant-a")

	var got domainpolicy.Policy
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		var err error
		got, err = tx.Policies().Get(ctx, tenantA, "policy-a", 2)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"policy_id":"policy-a"`, `"collection":`, `"detection":`, `"telemetry":`, `"response":`} {
		if !strings.Contains(string(got.DownlinkDocument), want) {
			t.Fatalf("downlink document %s missing %s", got.DownlinkDocument, want)
		}
	}
	if strings.Contains(string(got.DownlinkDocument), "tenant_id") || strings.Contains(string(got.DownlinkDocument), "published") {
		t.Fatalf("downlink document leaks Manager metadata: %s", got.DownlinkDocument)
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

func TestEffectiveAssignmentUsesSpecificityOrder(t *testing.T) {
	db := newPolicyTestDB(t)
	tenantID := mustAdapterTenantID(t, "tenant-a")
	for _, value := range []domainpolicy.Assignment{
		{ID: "scope-type", TenantID: tenantID, Target: domainpolicy.Target{ScopeType: "host"}, PolicyID: "policy-type", PolicyVersion: 1},
		{ID: "scope-exact", TenantID: tenantID, Target: domainpolicy.Target{ScopeType: "host", ScopeSelector: "prod"}, PolicyID: "policy-scope", PolicyVersion: 1},
		{ID: "agent", TenantID: tenantID, Target: domainpolicy.Target{AgentID: "agent-a"}, PolicyID: "policy-agent", PolicyVersion: 1},
	} {
		insertAssignment(t, db, value)
	}
	uow := NewUnitOfWork(db)

	var got []domainpolicy.Assignment
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		var err error
		got, err = tx.Assignments().Candidates(ctx, tenantID, domainpolicy.Target{
			AgentID: "agent-a", ScopeType: "host", ScopeSelector: "prod",
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].PolicyID != "policy-agent" || got[1].PolicyID != "policy-scope" || got[2].PolicyID != "policy-type" {
		t.Fatalf("Candidates() = %+v", got)
	}
	if _, err := db.Exec(`DELETE FROM policy_assignments WHERE assignment_id = ?`, "agent"); err != nil {
		t.Fatal(err)
	}
	err = uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		var err error
		got, err = tx.Assignments().Candidates(ctx, tenantID, domainpolicy.Target{
			AgentID: "agent-a", ScopeType: "host", ScopeSelector: "prod",
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].PolicyID != "policy-scope" {
		t.Fatalf("Candidates() = %+v", got)
	}
}

func TestControlRepositoryIsIdempotentForSameRequest(t *testing.T) {
	db := newPolicyTestDB(t)
	uow := NewUnitOfWork(db)
	tenantID := mustAdapterTenantID(t, "tenant-a")
	command := ports.PolicyControlCommand{
		ID: "command-a", TenantID: tenantID, AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 1,
		Payload: []byte(`{"policy_id":"policy-a","version":1}`), Actor: "admin-a", Reason: "deploy",
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
			return tx.Controls().Put(ctx, command)
		}); err != nil {
			t.Fatalf("attempt %d: Put() error = %v", attempt+1, err)
		}
	}
	assertRowCount(t, db, "control_commands", 1)
}

func TestControlRepositoryRejectsDifferentRequestWithSameID(t *testing.T) {
	db := newPolicyTestDB(t)
	uow := NewUnitOfWork(db)
	tenantID := mustAdapterTenantID(t, "tenant-a")
	command := ports.PolicyControlCommand{ID: "command-a", TenantID: tenantID, AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 1}
	if err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		return tx.Controls().Put(ctx, command)
	}); err != nil {
		t.Fatal(err)
	}
	command.PolicyVersion = 2
	err := uow.Execute(context.Background(), func(ctx context.Context, tx ports.PolicyTransaction) error {
		return tx.Controls().Put(ctx, command)
	})
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("Put() error kind = %q, want %q", failure.KindOf(err), failure.Conflict)
	}
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
		`CREATE TABLE policies (tenant_id TEXT, policy_id TEXT, version INTEGER, scope_type TEXT, scope_selector TEXT, protection_mode TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, policy_id, version))`,
		`CREATE TABLE rules (tenant_id TEXT, rule_id TEXT, version INTEGER, rule_where TEXT, data BLOB, PRIMARY KEY (tenant_id, rule_id, version))`,
		`CREATE TABLE policy_assignments (tenant_id TEXT, assignment_id TEXT, agent_id TEXT, scope_type TEXT, scope_selector TEXT, policy_id TEXT, policy_version INTEGER, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, assignment_id))`,
		`CREATE TABLE policy_audit (tenant_id TEXT, audit_id TEXT, action TEXT, policy_id TEXT, policy_version INTEGER, assignment_id TEXT, actor TEXT, status TEXT, reason TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, audit_id))`,
		`CREATE TABLE control_commands (tenant_id TEXT, command_id TEXT, agent_id TEXT, command_type TEXT, status TEXT, policy_id TEXT, policy_version INTEGER, actor TEXT, reason TEXT, created_at TIMESTAMP, updated_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, command_id))`,
		`CREATE TABLE policy_snapshot_outbox (tenant_id TEXT, policy_id TEXT, policy_version INTEGER, policy_document BLOB, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, published_at TIMESTAMP, attempt_count INTEGER DEFAULT 0, last_error TEXT DEFAULT '', PRIMARY KEY (tenant_id, policy_id, policy_version))`,
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

func ruleOnlyPolicyDocument(tenantID, policyID string, version uint64) string {
	return fmt.Sprintf(`{
		"tenant_id":%q,"policy_id":%q,"version":%d,"protection_mode":"rule-only",
		"collection":{"behaviors":["process.exec"]},
		"detection":{"rulesets":[{"ref":"ruleset:a","version":"v1"}]},
		"telemetry":{},"response_policy":{}
	}`, tenantID, policyID, version)
}

func insertAssignment(t *testing.T, db *sql.DB, value domainpolicy.Assignment) {
	t.Helper()
	document, err := encodeAssignment(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO policy_assignments (tenant_id, assignment_id, agent_id, scope_type, scope_selector, policy_id, policy_version, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		value.TenantID.String(), value.ID, value.Target.AgentID, value.Target.ScopeType, value.Target.ScopeSelector,
		value.PolicyID.String(), uint64(value.PolicyVersion), document); err != nil {
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
