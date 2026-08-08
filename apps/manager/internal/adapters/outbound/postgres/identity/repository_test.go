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

func newIdentityTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE agents (tenant_id TEXT, agent_id TEXT, host_id TEXT, version TEXT, data BLOB)`,
		`CREATE TABLE agent_health (tenant_id TEXT, agent_id TEXT, host_id TEXT, scope_type TEXT, scope_selector TEXT, observed_at TIMESTAMP, data BLOB)`,
		`CREATE TABLE agent_sessions (tenant_id TEXT, session_id TEXT, agent_id TEXT, status TEXT, data_transport TEXT, control_transport TEXT, last_ack_cursor TEXT, last_data_seen_at TIMESTAMP, last_control_seen_at TIMESTAMP, data BLOB)`,
		`CREATE TABLE tenant_metrics (tenant_id TEXT PRIMARY KEY, data BLOB)`,
		`CREATE TABLE rarity_baseline (tenant_id TEXT PRIMARY KEY, data BLOB)`,
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
