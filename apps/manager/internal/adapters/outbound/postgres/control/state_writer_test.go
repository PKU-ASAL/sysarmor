package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"

	_ "modernc.org/sqlite"
)

func TestStateWriterMergesCommandAckDocument(t *testing.T) {
	db := newStateWriterTestDB(t)
	_, err := db.Exec(`INSERT INTO control_commands (tenant_id,command_id,agent_id,status,data) VALUES ('tenant-a','command-a','agent-a','sent','{"command_id":"command-a","type":"policy_update","payload_json":{"policy_id":"policy-a"}}')`)
	if err != nil {
		t.Fatal(err)
	}
	ack := domaingateway.Ack{TenantID: "tenant-a", AgentID: "agent-a", ID: "command-a", Status: "applied", Message: "ok", PolicyID: "policy-a", PolicyVersion: 3, ReportJSON: `{"loaded":true}`, ObservedAt: time.Unix(100, 0).UTC()}
	if err := NewStateWriter(db).AckCommand(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	document := readStateDocument(t, db, "control_commands", "command_id", "command-a")
	if document["command_id"] != "command-a" || document["ack_policy_id"] != "policy-a" || document["ack_message"] != "ok" {
		t.Fatalf("document = %+v", document)
	}
}

func TestStateWriterPreservesEvidenceRequestFields(t *testing.T) {
	db := newStateWriterTestDB(t)
	_, err := db.Exec(`INSERT INTO evidence_pullbacks (tenant_id,request_id,agent_id,status,data) VALUES ('tenant-a','evidence-a','agent-a','pending','{"request_id":"evidence-a","incident_id":"incident-a","labels":{"case":"a"}}')`)
	if err != nil {
		t.Fatal(err)
	}
	result := domaingateway.EvidenceResult{TenantID: "tenant-a", AgentID: "agent-a", RequestID: "evidence-a", OK: true, Error: "collected", Evidence: []byte(`{"nodes":[]}`), ObservedAt: time.Unix(100, 0).UTC()}
	if err := NewStateWriter(db).CompleteEvidence(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	document := readStateDocument(t, db, "evidence_pullbacks", "request_id", "evidence-a")
	if document["incident_id"] != "incident-a" || document["status"] != "completed" || document["result"] != "collected" {
		t.Fatalf("document = %+v", document)
	}
}

func newStateWriterTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE control_commands (tenant_id TEXT,command_id TEXT,agent_id TEXT,status TEXT,acked_at TIMESTAMP,updated_at TIMESTAMP,data BLOB,PRIMARY KEY(tenant_id,command_id))`,
		`CREATE TABLE evidence_pullbacks (tenant_id TEXT,request_id TEXT,agent_id TEXT,status TEXT,updated_at TIMESTAMP,data BLOB,PRIMARY KEY(tenant_id,request_id))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func readStateDocument(t *testing.T, db *sql.DB, table, idColumn, id string) map[string]any {
	t.Helper()
	query := `SELECT data FROM ` + table + ` WHERE ` + idColumn + `=?`
	var raw []byte
	if err := db.QueryRow(query, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}
