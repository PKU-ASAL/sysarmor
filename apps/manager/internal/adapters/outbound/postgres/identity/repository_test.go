package identity

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	_ "modernc.org/sqlite"
)

func TestAgentRepositoryIsTenantScoped(t *testing.T) {
	db := newIdentityTestDB(t)
	insertIdentityAgent(t, db, "tenant-a", "agent-a", `{"agent_id":"wrong","tenant_id":"tenant-b","host_id":"host-a"}`)
	insertIdentityAgent(t, db, "tenant-b", "agent-b", `{"agent_id":"agent-b","tenant_id":"tenant-b"}`)
	tenantA := mustIdentityTenant(t, "tenant-a")
	repositories := NewRepositories(db)

	agents, err := repositories.Agents().List(context.Background(), tenantA, domainidentity.AgentFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].ID != "agent-a" || agents[0].TenantID != tenantA {
		t.Fatalf("agents = %+v", agents)
	}
}

func TestHealthRepositoryRejectsBlankTenant(t *testing.T) {
	db := newIdentityTestDB(t)
	_, err := NewRepositories(db).Health().List(context.Background(), tenant.ID(""), domainidentity.HealthFilter{})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("List() error kind = %q, want %q", failure.KindOf(err), failure.InvalidArgument)
	}
}

func TestHealthRepositoryCanonicalizesIdentity(t *testing.T) {
	db := newIdentityTestDB(t)
	insertIdentityHealth(t, db, "tenant-a", "agent-a", `{"agent_id":"wrong","tenant_id":"tenant-b","status":"ok","scope":{"type":"host"}}`)
	tenantA := mustIdentityTenant(t, "tenant-a")
	health, err := NewRepositories(db).Health().Get(context.Background(), tenantA, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if health.TenantID != tenantA || health.AgentID != "agent-a" || !strings.Contains(string(health.Document), `"tenant_id":"tenant-a"`) {
		t.Fatalf("health = %+v document=%s", health, health.Document)
	}
}

func TestHealthWriterUpsertsCanonicalProjection(t *testing.T) {
	db := newIdentityTestDB(t)
	tenantA := mustIdentityTenant(t, "tenant-a")
	writer := NewHealthWriter(db)
	health := domainidentity.Health{TenantID: tenantA, AgentID: "agent-a", HostID: "host-a", Status: "ok", Scope: domainidentity.Scope{Type: "host"}, Document: []byte(`{"tenant_id":"tenant-a","agent_id":"agent-a","status":"ok"}`)}
	if err := writer.Upsert(context.Background(), health); err != nil {
		t.Fatal(err)
	}
	health.Status = "degraded"
	health.Document = []byte(`{"tenant_id":"tenant-a","agent_id":"agent-a","status":"degraded"}`)
	if err := writer.Upsert(context.Background(), health); err != nil {
		t.Fatal(err)
	}
	stored, err := NewRepositories(db).Health().Get(context.Background(), tenantA, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "degraded" || stored.HostID != "host-a" || stored.Scope.Type != "host" {
		t.Fatalf("stored health = %+v", stored)
	}
}

func TestHealthWriterCanonicalizesDocumentIdentity(t *testing.T) {
	db := newIdentityTestDB(t)
	tenantA := mustIdentityTenant(t, "tenant-a")
	health := domainidentity.Health{TenantID: tenantA, AgentID: "agent-a", Document: []byte(`{"tenant_id":"tenant-b","agent_id":"agent-b","status":"ok"}`)}
	if err := NewHealthWriter(db).Upsert(context.Background(), health); err != nil {
		t.Fatal(err)
	}
	var document []byte
	if err := db.QueryRow(`SELECT data FROM agent_health WHERE tenant_id = ? AND agent_id = ?`, "tenant-a", "agent-a").Scan(&document); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document), "tenant-b") || strings.Contains(string(document), "agent-b") {
		t.Fatalf("stored document identity is not canonical: %s", document)
	}
}

func TestSessionRepositoryReadsNullableProjection(t *testing.T) {
	db := newIdentityTestDB(t)
	if _, err := db.Exec(`INSERT INTO agent_sessions (tenant_id, session_id, agent_id, data) VALUES (?, ?, ?, ?)`,
		"tenant-a", "session-a", "agent-a", []byte(`{"tenant_id":"wrong","session_id":"wrong","agent_id":"wrong","last_ack_cursor":"batch-7"}`)); err != nil {
		t.Fatal(err)
	}
	tenantA := mustIdentityTenant(t, "tenant-a")
	sessions, err := NewRepositories(db).Sessions().List(context.Background(), tenantA, domainidentity.SessionFilter{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != "session-a" || sessions[0].AgentID != "agent-a" || sessions[0].LastAckCursor != "batch-7" {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestSnapshotRepositoryReadsProductionMetricsAndRarityTables(t *testing.T) {
	db := newIdentityTestDB(t)
	if _, err := db.Exec(`INSERT INTO metrics (tenant_id, metric_key, data) VALUES (?, 'manager', ?)`, "tenant-a", []byte(`{"events_ingested":7}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO rarity_baseline (tenant_id, workload_key, signal_name, signal_count, data) VALUES (?, ?, ?, ?, '{}')`, "tenant-a", "host:a", "signal-a", 3); err != nil {
		t.Fatal(err)
	}
	tenantA := mustIdentityTenant(t, "tenant-a")
	snapshots := NewRepositories(db).Snapshots()
	metrics, err := snapshots.Metrics(context.Background(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := snapshots.Rarity(context.Background(), tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.EventsIngested != 7 || baseline.Count("host:a", "signal-a") != 3 {
		t.Fatalf("metrics=%+v baseline=%+v", metrics, baseline)
	}
}

func newIdentityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE agents (tenant_id TEXT, agent_id TEXT, host_id TEXT, version TEXT, observed_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, agent_id))`,
		`CREATE TABLE agent_health (tenant_id TEXT, agent_id TEXT, host_id TEXT, scope_type TEXT, scope_selector TEXT, observed_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, agent_id))`,
		`CREATE TABLE agent_sessions (tenant_id TEXT, session_id TEXT, agent_id TEXT, status TEXT, data_transport TEXT, control_transport TEXT, last_ack_cursor TEXT, started_at TIMESTAMP, last_seen_at TIMESTAMP, last_data_seen_at TIMESTAMP, last_control_seen_at TIMESTAMP, closed_at TIMESTAMP, data BLOB, PRIMARY KEY (tenant_id, session_id))`,
		`CREATE TABLE metrics (tenant_id TEXT, metric_key TEXT, data BLOB, PRIMARY KEY (tenant_id, metric_key))`,
		`CREATE TABLE rarity_baseline (tenant_id TEXT, workload_key TEXT, signal_name TEXT, signal_count INTEGER, data BLOB, PRIMARY KEY (tenant_id, workload_key, signal_name))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func insertIdentityAgent(t *testing.T, db *sql.DB, tenantID, agentID, document string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO agents (tenant_id, agent_id, data) VALUES (?, ?, ?)`, tenantID, agentID, []byte(document)); err != nil {
		t.Fatal(err)
	}
}

func insertIdentityHealth(t *testing.T, db *sql.DB, tenantID, agentID, document string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO agent_health (tenant_id, agent_id, data) VALUES (?, ?, ?)`, tenantID, agentID, []byte(document)); err != nil {
		t.Fatal(err)
	}
}

func mustIdentityTenant(t *testing.T, raw string) tenant.ID {
	t.Helper()
	id, err := tenant.NewID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
