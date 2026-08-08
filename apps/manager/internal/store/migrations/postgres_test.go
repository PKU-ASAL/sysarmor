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
		"evidence_pullbacks",
		"control_commands",
		"agent_sessions",
		"rarity_baseline",
		"metrics",
		"telemetry_batches",
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
	if len(ordered) != 3 || ordered[0].Version != 1 || ordered[1].Version != 2 || ordered[2].Version != 3 || ordered[2].Name != "tenant_telemetry_batches" {
		t.Fatalf("ordered migrations = %+v", ordered)
	}
	for _, want := range []string{"PRIMARY KEY (tenant_id, batch_id)", "processing", "completed", "lease_until"} {
		if !strings.Contains(ordered[2].SQL, want) {
			t.Fatalf("telemetry batch migration missing %q", want)
		}
	}
}
