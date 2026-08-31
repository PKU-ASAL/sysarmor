package migrations

import (
	"strings"
	"testing"
)

func TestPostgresSchemaCoversV3StoreTables(t *testing.T) {
	ordered := Ordered()
	allSchema := ""
	for _, migration := range ordered {
		allSchema += migration.SQL
	}
	for _, table := range []string{
		"schema_migrations",
		"agents",
		"agent_health",
		"rules",
		"policies",
		"policy_assignments",
		"policy_audit",
		"enrollments",
		"agent_unenrollments",
		"artifacts",
		"events",
		"signals",
		"response_audit",
		"response_decisions",
		"evidence_pullbacks",
		"control_commands",
		"agent_sessions",
		"rarity_baseline",
		"metrics",
	} {
		if !strings.Contains(allSchema, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("postgres schema missing table %s", table)
		}
	}
	for _, index := range []string{
		"idx_agents_host_id",
		"idx_agent_health_scope",
		"idx_policy_assignments_agent",
		"idx_policy_audit_policy",
		"idx_enrollments_token_hash",
		"idx_enrollments_bootstrap_token_hash",
		"idx_artifacts_lookup",
		"idx_events_labels",
		"idx_signals_labels_layer",
		"idx_signals_lineage",
		"idx_response_audit_agent",
		"idx_evidence_pullbacks_agent",
		"idx_control_commands_agent",
		"idx_agent_sessions_agent",
		"idx_rarity_baseline_workload",
	} {
		if !strings.Contains(PostgresSchema, "CREATE INDEX IF NOT EXISTS "+index) {
			t.Fatalf("postgres schema missing index %s", index)
		}
	}
	for _, removed := range []string{"incidents", "incident_events", "evidence"} {
		if strings.Contains(PostgresSchema, "CREATE TABLE IF NOT EXISTS "+removed+" (") {
			t.Fatalf("postgres schema still creates incident report table %s", removed)
		}
	}
	if len(ordered) != 7 || ordered[0].Version != 1 || ordered[1].Version != 2 || ordered[2].Version != 5 || ordered[3].Version != 6 || ordered[4].Version != 7 || ordered[5].Version != 10 || ordered[6].Version != 11 {
		t.Fatalf("ordered migrations = %+v", ordered)
	}
}

func TestPostgresMigrationsRetireWorkerTables(t *testing.T) {
	migration := Ordered()[5]
	for _, want := range []string{
		"DROP TABLE IF EXISTS worker_signal_processing",
		"DROP TABLE IF EXISTS worker_candidate_rejections",
		"DROP TABLE IF EXISTS telemetry_batches",
	} {
		if !strings.Contains(migration.SQL, want) {
			t.Fatalf("worker Signal processing migration missing %q", want)
		}
	}
}

func TestPostgresMigrationsReplaceLegacyPolicyModeWithoutInference(t *testing.T) {
	if !strings.Contains(PostgresSchema, "mode TEXT NOT NULL DEFAULT 'observe'") || strings.Contains(PostgresSchema, "protection_mode TEXT") {
		t.Fatal("published v1 policy schema must retain its original mode column")
	}
	policyMigration := Ordered()[4]
	assignments := strings.Index(policyMigration.SQL, "DELETE FROM policy_assignments")
	policies := strings.Index(policyMigration.SQL, "DELETE FROM policies")
	if assignments < 0 || policies < 0 || assignments > policies {
		t.Fatalf("v7 must delete assignments before policies: %s", policyMigration.SQL)
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS protection_mode TEXT",
		"DROP COLUMN IF EXISTS mode",
		"ALTER COLUMN protection_mode SET NOT NULL",
	} {
		if !strings.Contains(policyMigration.SQL, want) {
			t.Fatalf("v7 policy migration missing %q", want)
		}
	}
}

func TestPostgresMigrationsAddResponseDecisions(t *testing.T) {
	responseDecisions := Ordered()[3]
	if responseDecisions.Version != 6 || responseDecisions.Name != "response_decisions" {
		t.Fatalf("response decisions migration = %+v", responseDecisions)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS response_decisions",
		"PRIMARY KEY (tenant_id, audit_id)",
		"CREATE INDEX IF NOT EXISTS idx_response_decisions_response",
	} {
		if !strings.Contains(responseDecisions.SQL, want) {
			t.Fatalf("response decisions migration missing %q", want)
		}
	}
}

func TestPostgresMigrationsAddControlAudit(t *testing.T) {
	ordered := Ordered()
	controlAudit := ordered[2]
	if controlAudit.Version != 5 || controlAudit.Name != "control_audit" {
		t.Fatalf("control audit migration = %+v", controlAudit)
	}
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS control_audit",
		"PRIMARY KEY (tenant_id, audit_id)",
		"CREATE INDEX IF NOT EXISTS idx_control_audit_resource",
	} {
		if !strings.Contains(controlAudit.SQL, want) {
			t.Fatalf("control audit migration missing %q", want)
		}
	}
}
