package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestSessionRepositoryOpensTenantScopedControlState(t *testing.T) {
	db := newControlTestDB(t)
	insertControlFixture(t, db)
	result, err := NewSessionRepository(db).Open(context.Background(), "tenant-a", "agent-a", "host", "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if result.TenantID != "tenant-a" || result.AgentID != "agent-a" || result.SessionID == "" || result.ResumeCursor != "batch-7" {
		t.Fatalf("session = %+v", result)
	}
	for _, want := range []string{`"policy_id":"published"`, `"version":1`, `"collection"`, `"detection"`, `"telemetry"`, `"response"`} {
		if !strings.Contains(string(result.PolicyDocument), want) {
			t.Fatalf("policy %s missing %s", result.PolicyDocument, want)
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(result.PolicyDocument, &fields); err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"tenant_id", "published", "mode"} {
		if _, ok := fields[leaked]; ok {
			t.Fatalf("endpoint policy leaks Manager field %s: %s", leaked, result.PolicyDocument)
		}
	}
	if len(result.Messages) != 3 {
		t.Fatalf("messages = %+v", result.Messages)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM agent_sessions WHERE tenant_id = ? AND agent_id = ? AND control_transport = 'control'`, "tenant-a", "agent-a").Scan(&count); err != nil || count != 1 {
		t.Fatalf("control sessions = %d, err = %v", count, err)
	}
}

func TestSessionRepositoryRejectsMissingPublishedPolicy(t *testing.T) {
	db := newControlTestDB(t)
	_, err := NewSessionRepository(db).Open(context.Background(), "tenant-a", "agent-a", "host", "host-a")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Open() error = %v, want sql.ErrNoRows", err)
	}
}

func newControlTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	statements := []string{
		`CREATE TABLE policies (tenant_id TEXT, policy_id TEXT, version INTEGER, data BLOB, PRIMARY KEY (tenant_id, policy_id, version))`,
		`CREATE TABLE policy_assignments (tenant_id TEXT, assignment_id TEXT, agent_id TEXT, scope_type TEXT, scope_selector TEXT, policy_id TEXT, policy_version INTEGER, updated_at TIMESTAMP, PRIMARY KEY (tenant_id, assignment_id))`,
		`CREATE TABLE agent_sessions (tenant_id TEXT, session_id TEXT, agent_id TEXT, status TEXT, control_transport TEXT, last_ack_cursor TEXT, started_at TIMESTAMP, last_seen_at TIMESTAMP, last_control_seen_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, session_id))`,
		`CREATE TABLE response_audit (tenant_id TEXT, response_id TEXT, agent_id TEXT, status TEXT, created_at TIMESTAMP, command BLOB, PRIMARY KEY (tenant_id, response_id))`,
		`CREATE TABLE evidence_pullbacks (tenant_id TEXT, request_id TEXT, agent_id TEXT, status TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, request_id))`,
		`CREATE TABLE control_commands (tenant_id TEXT, command_id TEXT, agent_id TEXT, status TEXT, created_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, command_id))`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func insertControlFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	queries := []string{
		`INSERT INTO policies VALUES ('tenant-a','draft',2,'{"policy_id":"draft","published":false}')`,
		`INSERT INTO policies VALUES ('tenant-a','published',1,'{"tenant_id":"tenant-a","policy_id":"published","version":1,"protection_mode":"rule-only","collection":{"behaviors":["process.exec"]},"detection":{"rulesets":[{"ref":"ruleset:a","version":"v1"}]},"telemetry":{},"response_policy":{},"published":true}')`,
		`INSERT INTO policies VALUES ('tenant-b','foreign',9,'{"policy_id":"foreign","published":true}')`,
		`INSERT INTO policy_assignments VALUES ('tenant-a','assignment-a','agent-a','','','published',1,CURRENT_TIMESTAMP)`,
		`INSERT INTO agent_sessions VALUES ('tenant-a','data-a','agent-a','active','data','batch-7',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,NULL,'{}')`,
		`INSERT INTO response_audit VALUES ('tenant-a','response-a','agent-a','pending',CURRENT_TIMESTAMP,'{"response_id":"response-a"}')`,
		`INSERT INTO evidence_pullbacks VALUES ('tenant-a','evidence-a','agent-a','pending',CURRENT_TIMESTAMP,'{"request_id":"evidence-a"}')`,
		`INSERT INTO control_commands VALUES ('tenant-a','command-a','agent-a','pending',CURRENT_TIMESTAMP,'{"command_id":"command-a","type":"policy_update"}')`,
	}
	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
}
