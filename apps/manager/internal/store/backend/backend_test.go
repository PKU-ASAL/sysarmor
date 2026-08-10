package backend

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/api"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"google.golang.org/protobuf/encoding/protojson"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func commitBackendTelemetry(t *testing.T, st *store.Store, delta store.TelemetryBatchDelta) {
	t.Helper()
	claim, token, err := st.ClaimTelemetryBatch(context.Background(), delta.TenantID, delta.BatchID, time.Minute)
	if err != nil || claim != store.BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	delta.ClaimToken = token
	if err := st.CommitTelemetryBatch(context.Background(), delta); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFileAndMemoryBackends(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "store.json")
	file, err := Open(context.Background(), Options{Kind: KindFile, Path: filePath})
	if err != nil {
		t.Fatalf("Open(file) error = %v", err)
	}
	if file.Store == nil || file.Store.Info().Backend != "file" || file.Store.Info().Path != filePath {
		t.Fatalf("file result = %+v", file.Store.Info())
	}

	memory, err := Open(context.Background(), Options{Kind: KindMemory})
	if err != nil {
		t.Fatalf("Open(memory) error = %v", err)
	}
	if memory.Store == nil || memory.Store.Info().Backend != "memory" {
		t.Fatalf("memory result = %+v", memory.Store.Info())
	}
	if err := file.Close(); err != nil {
		t.Fatalf("file Close() error = %v", err)
	}
	if err := memory.Close(); err != nil {
		t.Fatalf("memory Close() error = %v", err)
	}
}

func TestOpenPostgresResultClosesDatabase(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	if got := fakeCloseCount(); got != 0 {
		t.Fatalf("close count before Close = %d, want 0", got)
	}
	if err := result.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := fakeCloseCount(); got == 0 {
		t.Fatal("postgres result did not close database connection")
	}
}

func TestOpenPostgresRunsMigrationAndPersistsSnapshot(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	if result.Migration.Version != 5 {
		t.Fatalf("migration version = %d, want 5", result.Migration.Version)
	}
	if result.Store == nil || result.Store.Info().Backend != KindPostgres {
		t.Fatalf("store info = %+v", result.Store.Info())
	}
	if execLog := fakeExecLog(); strings.Contains(execLog, "CREATE TABLE IF NOT EXISTS incidents") {
		t.Fatalf("postgres migration still creates incident reports: %s", execLog)
	} else if !strings.Contains(execLog, "CREATE TABLE IF NOT EXISTS agent_unenrollments") {
		t.Fatalf("postgres migration omitted agent unenrollment lifecycle: %s", execLog)
	}
	if _, err := result.Store.CreateResponse(responsemodel.Command{
		ResponseID: "resp-pg",
		TenantID:   "default",
		AgentID:    "agent-pg",
		Action:     "collect",
		Mode:       "observe",
	}); err != nil {
		t.Fatal(err)
	}
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	reopened, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("reopen postgres error = %v", err)
	}
	audits := reopened.Store.ListResponses("default", "agent-pg")
	if len(audits) != 1 || audits[0].Command.ResponseID != "resp-pg" {
		t.Fatalf("reopened audits = %+v", audits)
	}
}

func TestOpenPostgresProjectsAgentInventoryTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddAgent(store.AgentIdentity{
		TenantID: "default",
		AgentID:  "agent-inventory-pg",
		HostID:   "host-inventory-pg",
		Version:  "v-test",
	})
	result.Store.UpsertAgentHealth(agenthealth.AgentHealth{
		TenantID:   "default",
		AgentID:    "agent-health-pg",
		HostID:     "host-health-pg",
		Scope:      agenthealth.RuntimeScope{Type: "container", Selector: "checkout-api"},
		Status:     "ok",
		ObservedAt: time.Unix(123, 0).UTC(),
	})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO agents",
		"agent-inventory-pg",
		"host-inventory-pg",
		"v-test",
		"INSERT INTO agent_health",
		"agent-health-pg",
		"host-health-pg",
		"container",
		"checkout-api",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsResponseAuditTable(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	if _, err := result.Store.CreateResponse(responsemodel.Command{
		ResponseID: "resp-audit-pg",
		TenantID:   "default",
		AgentID:    "agent-audit-pg",
		Status:     "pending",
		Action:     "collect",
		Mode:       "observe",
		CreatedAt:  time.Unix(100, 0).UTC(),
		UpdatedAt:  time.Unix(101, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := result.Store.AckResponse(responsemodel.Ack{
		ResponseID:  "resp-audit-pg",
		TenantID:    "default",
		AgentID:     "agent-audit-pg",
		Accepted:    true,
		ObserveOnly: true,
		ObservedAt:  time.Unix(102, 0).UTC(),
	}); err != nil || !ok {
		t.Fatalf("AckResponse ok=%t err=%v", ok, err)
	}
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	if !strings.Contains(execLog, "ON CONFLICT (tenant_id, response_id) DO NOTHING") {
		t.Fatalf("response create is not create-only:\n%s", execLog)
	}
	for _, want := range []string{
		"INSERT INTO response_audit",
		"resp-audit-pg",
		"agent-audit-pg",
		"acked",
		"collect",
		"observe_only",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresWritesResponseAuditTablePath(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	now := time.Now().UTC()
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	if _, err := result.Store.CreateResponse(responsemodel.Command{
		ResponseID: "resp-write-table-pg",
		TenantID:   "default",
		AgentID:    "agent-response-write-pg",
		Status:     "pending",
		Action:     "collect",
		Mode:       "observe",
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := result.Store.AckResponse(responsemodel.Ack{
		ResponseID:  "resp-write-table-pg",
		TenantID:    "default",
		AgentID:     "agent-response-write-pg",
		Accepted:    true,
		ObserveOnly: true,
		ObservedAt:  now.Add(time.Second),
	}); err != nil || !ok {
		t.Fatalf("AckResponse ok=%t err=%v", ok, err)
	}
	execLog := fakeExecLog()
	if !strings.Contains(execLog, "INSERT INTO response_audit") || strings.Contains(execLog, "INSERT INTO sysarmor_state") {
		t.Fatalf("response write hook did not use table path without snapshot save:\n%s", execLog)
	}
	records := result.Store.ListResponses("default", "agent-response-write-pg")
	if len(records) != 1 || records[0].Command.ResponseID != "resp-write-table-pg" || records[0].Command.Status != "acked" || records[0].Ack == nil || !records[0].Ack.Accepted {
		t.Fatalf("response audit table write/read = %+v", records)
	}
}

func TestOpenPostgresDurableControlPathsWorkAfterReopen(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Store.CreateResponse(responsemodel.Command{
		ResponseID: "response-reopen", TenantID: "default", AgentID: "agent-reopen", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "policy-reopen", 9, false
	if _, err := result.Store.UpsertPolicyWithError(policy); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pending := reopened.Store.PendingResponses("default", "agent-reopen"); len(pending) != 1 || pending[0].ResponseID != "response-reopen" {
		t.Fatalf("pending responses after reopen = %+v", pending)
	}
	if _, ok, err := reopened.Store.AckResponse(responsemodel.Ack{ResponseID: "response-reopen", TenantID: "default", AgentID: "agent-reopen"}); err != nil || !ok {
		t.Fatalf("AckResponse after reopen ok=%t err=%v", ok, err)
	}
	if _, ok, err := reopened.Store.PublishPolicyWithAudit("default", "policy-reopen", 9, true, policymodel.AuditRecord{Action: "policy.publish"}); err != nil || !ok {
		t.Fatalf("PublishPolicyWithAudit after reopen ok=%t err=%v", ok, err)
	}
	assignment, _, ok, err := reopened.Store.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-reopen", PolicyID: "policy-reopen", PolicyVersion: 9},
		policymodel.AuditRecord{Action: "policy.assign"}, nil,
	)
	if err != nil || !ok || assignment.PolicyVersion != 9 {
		t.Fatalf("AssignPolicyWithAudit after reopen assignment=%+v ok=%t err=%v", assignment, ok, err)
	}
}

func TestOpenPostgresStaleSaveDoesNotOverwriteControlAckFromAnotherStore(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	manager, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Store.CreateControlCommand(controlmodel.ControlCommand{
		CommandID: "control-cross-store", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusPending,
	}); err != nil {
		t.Fatal(err)
	}
	gatewayStore, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := gatewayStore.Store.AckControlCommand(controlmodel.ControlCommandAck{
		CommandID: "control-cross-store", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusApplied,
		ObservedAt: time.Now().UTC().Add(time.Second),
	}); err != nil || !ok {
		t.Fatalf("AckControlCommand ok=%t err=%v", ok, err)
	}
	if err := manager.Store.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	commands := reopened.Store.ListControlCommands("default", "agent-a", "")
	if len(commands) != 1 || commands[0].Status != controlmodel.ControlCommandStatusApplied {
		t.Fatalf("control commands after stale cross-store save = %+v", commands)
	}
	if log := fakeExecLog(); !strings.Contains(log, "WHERE control_commands.updated_at <= EXCLUDED.updated_at") {
		t.Fatalf("control command upsert missing monotonic guard:\n%s", log)
	}
}

func TestOpenPostgresSaveDoesNotReplayExplicitControlPlaneTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.Store.CreateResponse(responsemodel.Command{ResponseID: "response-save-owner", TenantID: "default", AgentID: "agent-a"}); err != nil {
		t.Fatal(err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "policy-save-owner", 1, true
	if _, err := result.Store.UpsertPolicyWithError(policy); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := result.Store.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: policy.PolicyID, PolicyVersion: 1},
		policymodel.AuditRecord{AuditID: "audit-save-owner", Action: "policy.assign"}, nil,
	); err != nil || !ok {
		t.Fatalf("AssignPolicyWithAudit ok=%t err=%v", ok, err)
	}
	fakeClearExecLog()

	if err := result.Store.Save(); err != nil {
		t.Fatal(err)
	}
	log := fakeExecLog()
	for _, forbidden := range []string{"INSERT INTO response_audit", "INSERT INTO policies", "INSERT INTO policy_assignments", "INSERT INTO policy_audit"} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("Save replayed explicitly owned table %q:\n%s", forbidden, log)
		}
	}
}

func TestOpenPostgresProjectsPolicyTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "policy-table-pg"
	policy.Version = 9
	policy.Scope = policymodel.ScopeSelector{Type: "container", Selector: "checkout-api"}
	policy.Mode = "observe"
	result.Store.UpsertPolicy(policy)
	assignment, ok, err := result.Store.AssignPolicy(policymodel.Assignment{
		TenantID:      "default",
		AgentID:       "agent-policy-pg",
		PolicyID:      "policy-table-pg",
		PolicyVersion: 9,
	})
	if err != nil || !ok {
		t.Fatalf("AssignPolicy() ok=%t err=%v", ok, err)
	}
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO policies",
		"policy-table-pg",
		"container",
		"checkout-api",
		"observe",
		"INSERT INTO policy_assignments",
		assignment.AssignmentID,
		"agent-policy-pg",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresWritesPolicyControlTablePaths(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "policy-write-table-pg"
	policy.Version = 4
	policy.Published = false
	result.Store.UpsertPolicy(policy)
	published, ok, err := result.Store.PublishPolicyWithAudit("default", "policy-write-table-pg", 4, true, policymodel.AuditRecord{
		AuditID: "audit-policy-publish-pg", Action: "policy.publish", Actor: "alice", CreatedAt: time.Unix(129, 0).UTC(),
	})
	if err != nil || !ok || !published.Published {
		t.Fatalf("PublishPolicy() = %+v ok=%t err=%v", published, ok, err)
	}
	assignment, _, ok, err := result.Store.AssignPolicyWithAudit(policymodel.Assignment{
		TenantID:      "default",
		AgentID:       "agent-policy-write-pg",
		PolicyID:      "policy-write-table-pg",
		PolicyVersion: 4,
	}, policymodel.AuditRecord{
		AuditID:   "audit-policy-write-pg",
		Action:    "policy.assign",
		Actor:     "alice",
		Status:    "ok",
		Reason:    "table write",
		CreatedAt: time.Unix(130, 0).UTC(),
	}, nil)
	if err != nil || !ok {
		t.Fatalf("AssignPolicy() ok=%t err=%v", ok, err)
	}
	if assignment.AssignmentID == "" {
		t.Fatal("AssignPolicyWithAudit assignment_id is empty")
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO policies",
		"INSERT INTO policy_assignments",
		"INSERT INTO policy_audit",
		"policy-write-table-pg",
		"agent-policy-write-pg",
		"audit-policy-write-pg",
		"table write",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
	if strings.Contains(execLog, "INSERT INTO sysarmor_state") {
		t.Fatalf("policy write hook unexpectedly used snapshot save:\n%s", execLog)
	}
	got, ok := result.Store.EffectivePolicy("default", "agent-policy-write-pg", "", "")
	if !ok || got.PolicyID != "policy-write-table-pg" || got.Version != 4 || !got.Published {
		t.Fatalf("effective policy from table write path = %+v, %v", got, ok)
	}
}

func TestOpenPostgresRollsBackPolicyAssignmentWhenAuditWriteFails(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "policy-tx-rollback", 1, true
	if _, err := result.Store.UpsertPolicyWithError(policy); err != nil {
		t.Fatal(err)
	}
	fakeFailExecContaining("INSERT INTO policy_audit", errors.New("audit write failed"))

	_, _, ok, err := result.Store.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: policy.PolicyID, PolicyVersion: 1},
		policymodel.AuditRecord{AuditID: "audit-tx-rollback", Action: "policy.assign"},
		&controlmodel.ControlCommand{CommandID: "control-tx-rollback", Type: controlmodel.ControlCommandTypePolicyUpdate},
	)

	commits, rollbacks := fakeTransactionCounts()
	if err == nil || ok || commits != 0 || rollbacks != 1 {
		t.Fatalf("AssignPolicyWithAudit ok=%t err=%v commits=%d rollbacks=%d", ok, err, commits, rollbacks)
	}
	if log := fakeExecLog(); !strings.Contains(log, "INSERT INTO policy_assignments") || !strings.Contains(log, "INSERT INTO policy_audit") || strings.Contains(log, "control-tx-rollback") {
		t.Fatalf("unexpected transaction exec log:\n%s", log)
	}
	if len(result.Store.Assignments) != 0 || len(result.Store.PolicyAudits) != 0 || len(result.Store.ControlCommands) != 0 {
		t.Fatalf("failed transaction published memory state: assignments=%+v audits=%+v commands=%+v", result.Store.Assignments, result.Store.PolicyAudits, result.Store.ControlCommands)
	}
}

func TestOpenPostgresCommitsIdenticalPolicyAssignmentCommandReplay(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "policy-command-conflict", 1, true
	if _, err := result.Store.UpsertPolicyWithError(policy); err != nil {
		t.Fatal(err)
	}
	assignment := policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: policy.PolicyID, PolicyVersion: 1}
	audit := policymodel.AuditRecord{AuditID: "audit-command-replay", Action: "policy.assign"}
	command := &controlmodel.ControlCommand{CommandID: "control-command-replay", Type: controlmodel.ControlCommandTypePolicyUpdate}
	_, firstCommand, ok, err := result.Store.AssignPolicyWithAudit(assignment, audit, command)
	if err != nil || !ok || firstCommand == nil {
		t.Fatalf("initial AssignPolicyWithAudit command=%+v ok=%t err=%v", firstCommand, ok, err)
	}
	fakeReturnZeroRowsContaining("INSERT INTO control_commands")
	_, replayedCommand, ok, err := result.Store.AssignPolicyWithAudit(assignment, audit, command)

	commits, rollbacks := fakeTransactionCounts()
	if err != nil || !ok || commits != 1 || rollbacks != 0 {
		t.Fatalf("AssignPolicyWithAudit ok=%t err=%v commits=%d rollbacks=%d", ok, err, commits, rollbacks)
	}
	if replayedCommand == nil || !replayedCommand.CreatedAt.Equal(firstCommand.CreatedAt) {
		t.Fatalf("replayed command = %+v, want original %+v", replayedCommand, firstCommand)
	}
	if len(result.Store.Assignments) != 1 || len(result.Store.PolicyAudits) != 1 || len(result.Store.ControlCommands) != 1 {
		t.Fatalf("replayed transaction not published: assignments=%+v audits=%+v commands=%+v", result.Store.Assignments, result.Store.PolicyAudits, result.Store.ControlCommands)
	}
}

func TestOpenPostgresRejectsPolicyAssignmentCommandPayloadConflict(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "policy-command-conflict", 1, true
	if _, err := result.Store.UpsertPolicyWithError(policy); err != nil {
		t.Fatal(err)
	}
	existing, err := json.Marshal(controlmodel.ControlCommand{
		CommandID: "control-command-conflict",
		TenantID:  "default",
		AgentID:   "agent-other",
		Type:      controlmodel.ControlCommandTypePolicyUpdate,
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeSetControlCommandRows(existing)
	fakeReturnZeroRowsContaining("INSERT INTO control_commands")

	_, _, ok, err := result.Store.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: policy.PolicyID, PolicyVersion: 1},
		policymodel.AuditRecord{AuditID: "audit-command-conflict", Action: "policy.assign"},
		&controlmodel.ControlCommand{CommandID: "control-command-conflict", Type: controlmodel.ControlCommandTypePolicyUpdate},
	)

	commits, rollbacks := fakeTransactionCounts()
	if !errors.Is(err, store.ErrConflict) || ok || commits != 0 || rollbacks != 1 {
		t.Fatalf("AssignPolicyWithAudit ok=%t err=%v commits=%d rollbacks=%d", ok, err, commits, rollbacks)
	}
}

func TestOpenPostgresProjectsControlAuditTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.RecordPolicyAudit(policymodel.AuditRecord{
		AuditID:       "audit-control-pg",
		TenantID:      "default",
		Action:        "policy.assign",
		PolicyID:      "policy-control-pg",
		PolicyVersion: 3,
		AssignmentID:  "assignment-control-pg",
		Actor:         "alice",
		Status:        "ok",
		Reason:        "test projection",
		CreatedAt:     time.Unix(110, 0).UTC(),
	})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO policy_audit",
		"audit-control-pg",
		"policy.assign",
		"policy-control-pg",
		"assignment-control-pg",
		"test projection",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsRuleAndPullbackTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.UpsertRule(policymodel.RuleContent{
		RuleID:         "rule-table-pg",
		Version:        3,
		Enabled:        true,
		Where:          "endpoint",
		Severity:       "critical",
		Tags:           []string{"c2", "network"},
		MITRE:          []string{"T1571"},
		ResponseIntent: "collect",
	})
	result.Store.CreateEvidencePullback(controlmodel.EvidencePullbackRequest{
		RequestID:  "evpb-table-pg",
		TenantID:   "default",
		AgentID:    "agent-pullback-pg",
		IncidentID: "inc-pullback-pg",
		Labels:     map[string]string{"scenario": "pg-pullback"},
		Target:     "process:p1",
		Status:     controlmodel.EvidencePullbackStatusPending,
		CreatedAt:  time.Unix(200, 0).UTC(),
		UpdatedAt:  time.Unix(201, 0).UTC(),
	})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO rules",
		"rule-table-pg",
		"endpoint",
		"true",
		"4",
		"c2\x1fnetwork",
		"T1571",
		"INSERT INTO evidence_pullbacks",
		"evpb-table-pg",
		"agent-pullback-pg",
		"inc-pullback-pg",
		"pg-pullback",
		"pending",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsAndQueriesControlCommands(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	now := time.Now().UTC()
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	if _, err := result.Store.CreateControlCommand(controlmodel.ControlCommand{
		CommandID:      "ctrl-table-pg",
		TenantID:       "default",
		AgentID:        "agent-control-pg",
		Type:           controlmodel.ControlCommandTypeContentUpdate,
		Status:         controlmodel.ControlCommandStatusPending,
		ContentRef:     "ioc:pg",
		ContentKind:    "iocpack",
		ContentVersion: "v1",
		PayloadJSON:    []byte(`{"kind":"iocpack"}`),
		Actor:          "operator",
		Reason:         "postgres projection",
		CreatedAt:      time.Unix(210, 0).UTC(),
		UpdatedAt:      time.Unix(211, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if execLog := fakeExecLog(); !strings.Contains(execLog, "ON CONFLICT (tenant_id, command_id) DO NOTHING") {
		t.Fatalf("control command create is not create-only:\n%s", execLog)
	}
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO control_commands",
		"ctrl-table-pg",
		"agent-control-pg",
		"content_update",
		"ioc:pg",
		"postgres projection",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}

	reopened, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("reopen postgres error = %v", err)
	}
	pending := reopened.Store.PendingControlCommands("default", "agent-control-pg")
	if len(pending) != 1 || pending[0].CommandID != "ctrl-table-pg" || pending[0].ContentRef != "ioc:pg" {
		t.Fatalf("pending control commands = %+v", pending)
	}
	if _, ok := reopened.Store.MarkControlCommandSent("ctrl-table-pg", "default", "agent-control-pg", now.Add(time.Second)); !ok {
		t.Fatal("MarkControlCommandSent ok = false")
	}
	if _, ok, err := reopened.Store.AckControlCommand(controlmodel.ControlCommandAck{
		CommandID:  "ctrl-table-pg",
		TenantID:   "default",
		AgentID:    "agent-control-pg",
		Status:     controlmodel.ControlCommandStatusApplied,
		Message:    "applied",
		ObservedAt: now.Add(2 * time.Second),
	}); err != nil || !ok {
		t.Fatalf("AckControlCommand ok=%t err=%v", ok, err)
	}
	if err := reopened.Store.Save(); err != nil {
		t.Fatalf("Save acked command error = %v", err)
	}
	commands := reopened.Store.ListControlCommands("default", "agent-control-pg", controlmodel.ControlCommandTypeContentUpdate)
	if len(commands) != 1 || commands[0].Status != controlmodel.ControlCommandStatusApplied || commands[0].AckMessage != "applied" {
		t.Fatalf("acked control commands = %+v", commands)
	}
	if got := reopened.Store.PendingControlCommands("default", "agent-control-pg"); len(got) != 0 {
		t.Fatalf("pending after ack = %+v", got)
	}
}

// Telemetry (events and signals) is intentionally not projected into the
// relational backend; it lives in the index tier and the in-process working
// set. Save must persist platform state without touching event/signal tables.
func TestOpenPostgresDoesNotProjectEventSignalTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddAgent(store.AgentIdentity{TenantID: "default", AgentID: "agent-ingest-pg", HostID: "host-ingest-pg"})
	result.Store.AddEvent(&eventv1.CanonicalEvent{
		Id:       "ev-table-pg",
		Labels:   pgLabels("pg-ingest"),
		Behavior: "network.connect",
		AgentId:  "agent-ingest-pg",
		HostId:   "host-ingest-pg",
	})
	result.Store.AddSignal(&signalv1.Signal{
		Id:        "sig-table-pg",
		Labels:    pgLabels("pg-ingest"),
		Name:      "reverse_shell_pattern",
		Where:     signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		LineageId: "lin-table-pg",
		Terminal:  true,
	})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	if !strings.Contains(execLog, "INSERT INTO agents") {
		t.Fatalf("postgres exec log missing platform-state projection (agents):\n%s", execLog)
	}
	for _, forbidden := range []string{"INSERT INTO events", "INSERT INTO signals"} {
		if strings.Contains(execLog, forbidden) {
			t.Fatalf("postgres exec log unexpectedly projected telemetry %q:\n%s", forbidden, execLog)
		}
	}
}

func TestOpenPostgresServesEventsFromMemory(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddEvent(&eventv1.CanonicalEvent{
		Id:       "ev-query-table-pg",
		Labels:   pgLabels("pg-query-table"),
		Behavior: "process.exec",
		AgentId:  "agent-query-table-pg",
	})
	events := result.Store.ListEvents(pgSelector("pg-query-table"), "process.exec")
	if len(events) != 1 || events[0].GetId() != "ev-query-table-pg" || events[0].GetLabels()["scenario"] != "pg-query-table" {
		t.Fatalf("events from memory working set = %+v", events)
	}
	if strings.Contains(fakeLastQuery(), "SELECT data FROM events") {
		t.Fatalf("ListEvents should serve telemetry from memory, not query postgres: %s", fakeLastQuery())
	}
}

func TestOpenPostgresServesSignalsFromMemory(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddSignal(&signalv1.Signal{
		Id:       "sig-query-table-pg",
		Labels:   pgLabels("pg-query-table"),
		Name:     "reverse_shell_pattern",
		Where:    signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		Terminal: true,
	})
	signals := result.Store.ListSignals(pgSelector("pg-query-table"), "endpoint", true)
	if len(signals) != 1 || signals[0].GetId() != "sig-query-table-pg" || !signals[0].GetTerminal() {
		t.Fatalf("signals from memory working set = %+v", signals)
	}
	if strings.Contains(fakeLastQuery(), "SELECT data FROM signals") {
		t.Fatalf("ListSignals should serve telemetry from memory, not query postgres: %s", fakeLastQuery())
	}
}

func TestOpenPostgresQueriesIncidentsFromTablePath(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	raw, err := protojson.Marshal(&incidentv1.Incident{
		Id:      "inc-query-table-pg",
		Labels:  pgLabels("pg-query-table"),
		Summary: "incident from table path",
	})
	if err != nil {
		t.Fatalf("marshal incident: %v", err)
	}
	fakeSetIncidentRows(raw)
	incidents := result.Store.ListIncidents(pgSelector("pg-query-table"))
	if len(incidents) != 0 {
		t.Fatalf("incidents from postgres table = %+v, want none", incidents)
	}
	if strings.Contains(fakeLastQuery(), "SELECT data FROM incidents") {
		t.Fatalf("ListIncidents queried postgres: %s", fakeLastQuery())
	}
}

func TestOpenPostgresQueriesResponseAuditFromTablePath(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	commandRaw, err := json.Marshal(responsemodel.Command{
		ResponseID: "resp-query-table-pg",
		TenantID:   "default",
		AgentID:    "agent-response-query-pg",
		Action:     "collect",
		Mode:       "observe",
		Status:     "acked",
	})
	if err != nil {
		t.Fatalf("marshal response command: %v", err)
	}
	ackRaw, err := json.Marshal(responsemodel.Ack{
		ResponseID:  "resp-query-table-pg",
		TenantID:    "default",
		AgentID:     "agent-response-query-pg",
		Accepted:    true,
		ObserveOnly: true,
	})
	if err != nil {
		t.Fatalf("marshal response ack: %v", err)
	}
	fakeSetResponseRows(commandRaw, ackRaw)
	records := result.Store.ListResponses("default", "agent-response-query-pg")
	if len(records) != 1 || records[0].Command.ResponseID != "resp-query-table-pg" || records[0].Ack == nil || !records[0].Ack.Accepted {
		t.Fatalf("response audit from postgres table = %+v", records)
	}
	if !strings.Contains(fakeLastQuery(), "SELECT command, ack FROM response_audit") {
		t.Fatalf("ListResponses did not query response_audit table: %s", fakeLastQuery())
	}
}

func TestOpenPostgresQueriesPolicyControlTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "policy-query-table-pg"
	policy.Version = 12
	policy.Published = true
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	assignment := policymodel.Assignment{
		AssignmentID:  "assignment-query-table-pg",
		TenantID:      "default",
		AgentID:       "agent-policy-query-pg",
		PolicyID:      "policy-query-table-pg",
		PolicyVersion: 12,
	}
	assignmentRaw, err := json.Marshal(assignment)
	if err != nil {
		t.Fatalf("marshal assignment: %v", err)
	}
	fakeSetPolicyRows(policyRaw)
	policies := result.Store.ListPolicies("default")
	if len(policies) != 1 || policies[0].PolicyID != "policy-query-table-pg" || policies[0].Version != 12 {
		t.Fatalf("policies from postgres table = %+v", policies)
	}
	if !strings.Contains(fakeLastQuery(), "SELECT data FROM policies") {
		t.Fatalf("ListPolicies did not query policies table: %s", fakeLastQuery())
	}
	fakeSetAssignmentRows(assignmentRaw)
	assignments := result.Store.ListAssignments("default", "agent-policy-query-pg")
	if len(assignments) != 1 || assignments[0].AssignmentID != "assignment-query-table-pg" || assignments[0].PolicyID != "policy-query-table-pg" {
		t.Fatalf("assignments from postgres table = %+v", assignments)
	}
	if !strings.Contains(fakeLastQuery(), "SELECT data FROM policy_assignments") {
		t.Fatalf("ListAssignments did not query policy_assignments table: %s", fakeLastQuery())
	}
}

func TestOpenPostgresGetsPolicyFromTablePath(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "policy-get-table-pg"
	policy.Version = 21
	policy.Published = true
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	fakeSetPolicyRows(policyRaw)
	got, ok := result.Store.GetPolicy("default", "policy-get-table-pg", 21)
	if !ok || got.PolicyID != "policy-get-table-pg" || got.Version != 21 {
		t.Fatalf("GetPolicy from postgres table = %+v, %v", got, ok)
	}
	if !strings.Contains(fakeLastQuery(), "SELECT data FROM policies") {
		t.Fatalf("GetPolicy did not query policies table: %s", fakeLastQuery())
	}
}

func TestOpenPostgresQueriesEffectivePolicyFromTablePath(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "policy-effective-table-pg"
	policy.Version = 7
	policy.Published = true
	policy.CloudRules = []string{"web_shell_chain"}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	assignment := policymodel.Assignment{
		AssignmentID:  "assignment-effective-table-pg",
		TenantID:      "default",
		AgentID:       "agent-effective-query-pg",
		PolicyID:      "policy-effective-table-pg",
		PolicyVersion: 7,
	}
	assignmentRaw, err := json.Marshal(assignment)
	if err != nil {
		t.Fatalf("marshal assignment: %v", err)
	}
	fakeSetPolicyRows(policyRaw)
	fakeSetAssignmentRows(assignmentRaw)
	got, ok := result.Store.EffectivePolicy("default", "agent-effective-query-pg", "", "")
	if !ok || got.PolicyID != "policy-effective-table-pg" || got.Version != 7 || len(got.CloudRules) != 1 {
		t.Fatalf("EffectivePolicy from postgres table = %+v, %v", got, ok)
	}
	if !strings.Contains(fakeLastQuery(), "SELECT data FROM policies") {
		t.Fatalf("EffectivePolicy did not query policies table: %s", fakeLastQuery())
	}
}

func TestOpenPostgresProjectsIncidentEvidenceTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddIncident(&incidentv1.Incident{
		Id:       "inc-table-pg",
		Labels:   pgLabels("pg-incident"),
		Summary:  "projected incident",
		Severity: 70,
		Evidence: &incidentv1.EvidenceSubgraph{
			Nodes: []*incidentv1.GraphNode{{
				Id:    "process:p-incident",
				Kind:  "process",
				Label: "bash",
			}},
			Edges: []*incidentv1.GraphEdge{{
				Id:   "edge-process-socket",
				From: "process:p-incident",
				To:   "socket:10.77.0.5:443",
				Kind: "connects_to",
			}},
		},
	})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, removed := range []string{
		"INSERT INTO incidents",
		"INSERT INTO evidence",
	} {
		if strings.Contains(execLog, removed) {
			t.Fatalf("postgres exec log contains removed projection %s:\n%s", removed, execLog)
		}
	}
}

func TestOpenPostgresProjectsIncidentEventsAndMetricsTables(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.AddIncident(&incidentv1.Incident{
		Id:      "inc-event-pg",
		Labels:  pgLabels("pg-incident-event"),
		Summary: "projected incident events",
		ContributingSignals: []*signalv1.Signal{{
			Id:        "sig-event-ref-pg",
			Labels:    pgLabels("pg-incident-event"),
			Name:      "reverse_shell_pattern",
			Where:     signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
			LineageId: "lin-event-pg",
			EventRefs: []string{"ev-ref-a"},
			Evidence: &signalv1.EvidenceBundle{
				EventRefs: []string{"ev-ref-b"},
			},
		}},
	})
	commitBackendTelemetry(t, result.Store, store.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "metrics-batch", Metrics: store.Metrics{DataBatchesAppended: 1, EventsIngested: 2, SignalsEmitted: 2}})
	execLog := fakeExecLog()
	if strings.Contains(execLog, "INSERT INTO incident_events") {
		t.Fatalf("postgres exec log contains incident event projection:\n%s", execLog)
	}
	for _, want := range []string{
		"INSERT INTO metrics",
		"manager",
		`"data_batches_appended":1`,
		`"events_ingested":2`,
		`"signals_emitted":2`,
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsAgentSessionTable(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	result.Store.RecordControlSessionOpen("default", "agent-session-pg", "control", time.Unix(300, 0).UTC())
	result.Store.RecordDataBatchAppend(store.AgentIdentity{
		TenantID: "default",
		AgentID:  "agent-session-pg",
	}, "batch-agent-session-pg", "grpc", time.Unix(301, 0).UTC())
	result.Store.CloseAgentSession("default", "agent-session-pg", time.Unix(302, 0).UTC())
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO agent_sessions",
		"agent-session-pg",
		"closed",
		"grpc",
		"batch-agent-session-pg",
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsRarityBaselineTable(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	baseline := rarity.Baseline{}
	baseline.Observe([]*signalv1.Signal{{
		Name: "download_by_lolbin",
		Entities: []*signalv1.EntityRef{{
			Kind: "container",
			Key:  "checkout-api",
		}},
	}, {
		Name: "reverse_shell_pattern",
	}})
	commitBackendTelemetry(t, result.Store, store.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "rarity-batch", Rarity: baseline})
	execLog := fakeExecLog()
	for _, want := range []string{
		"INSERT INTO rarity_baseline",
		"container:checkout-api",
		"download_by_lolbin",
		"global",
		"reverse_shell_pattern",
		`"signal_count":1`,
	} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %s:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresProjectsTenantMetricsAndRarity(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn",
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline := rarity.Baseline{}
	baseline.Observe([]*signalv1.Signal{{Name: "tenant-signal"}})
	commitBackendTelemetry(t, result.Store, store.TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "tenant-batch", Metrics: store.Metrics{DataBatchesAppended: 1, EventsIngested: 3, SignalsEmitted: 2}, Rarity: baseline})
	execLog := fakeExecLog()
	for _, want := range []string{"INSERT INTO metrics", "tenant-a", `"events_ingested":3`, "INSERT INTO rarity_baseline", "tenant-signal"} {
		if !strings.Contains(execLog, want) {
			t.Fatalf("postgres exec log missing %q:\n%s", want, execLog)
		}
	}
}

func TestOpenPostgresPreservesIdempotentIngestAcrossReopen(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	event := &eventv1.CanonicalEvent{Id: "ev-pg-idempotent", Labels: pgLabels("pg-idempotent"), Behavior: "process.exec"}
	signal := &signalv1.Signal{Id: "sig-pg-idempotent", Labels: pgLabels("pg-idempotent"), Name: "reverse_shell_pattern", Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT}
	if !result.Store.AddEvent(event) || result.Store.AddEvent(event) {
		t.Fatal("event idempotency failed before save")
	}
	if !result.Store.AddSignal(signal) || result.Store.AddSignal(signal) {
		t.Fatal("signal idempotency failed before save")
	}
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reopened, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("reopen postgres error = %v", err)
	}
	if reopened.Store.AddEvent(event) {
		if err := reopened.Store.Save(); err != nil {
			t.Fatalf("Save() duplicate event error = %v", err)
		}
	}
	if reopened.Store.AddSignal(signal) {
		if err := reopened.Store.Save(); err != nil {
			t.Fatalf("Save() duplicate signal error = %v", err)
		}
	}
	if got := reopened.Store.ListEvents(pgSelector("pg-idempotent"), ""); len(got) != 1 || got[0].GetId() != event.GetId() {
		t.Fatalf("events after duplicate replay = %+v", got)
	}
	if got := reopened.Store.ListSignals(pgSelector("pg-idempotent"), "endpoint", false); len(got) != 1 || got[0].GetId() != signal.GetId() {
		t.Fatalf("signals after duplicate replay = %+v", got)
	}
}

func TestOpenPostgresPersistsPolicyAndIncidentStateAcrossReopen(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "postgres-policy"
	policy.Version = 7
	policy.Published = false
	result.Store.UpsertPolicy(policy)
	published, ok, err := result.Store.PublishPolicy("default", "postgres-policy", 7, true)
	if err != nil || !ok || !published.Published {
		t.Fatalf("PublishPolicy() = %+v ok=%t err=%v", published, ok, err)
	}
	assignment, ok, err := result.Store.AssignPolicy(policymodel.Assignment{
		TenantID:      "default",
		AgentID:       "agent-pg-policy",
		PolicyID:      "postgres-policy",
		PolicyVersion: 7,
	})
	if err != nil || !ok {
		t.Fatalf("AssignPolicy() ok=%t err=%v", ok, err)
	}
	result.Store.RecordPolicyAudit(policymodel.AuditRecord{
		TenantID:      "default",
		Action:        "policy.assign",
		PolicyID:      "postgres-policy",
		PolicyVersion: 7,
		AssignmentID:  assignment.AssignmentID,
		Actor:         "tester",
	})
	result.Store.AddIncident(&incidentv1.Incident{Id: "inc-pg", Labels: pgLabels("pg-policy"), Summary: "persisted incident"})
	if err := result.Store.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	reopened, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("reopen postgres error = %v", err)
	}
	effective, ok := reopened.Store.EffectivePolicy("default", "agent-pg-policy", "", "")
	if !ok || effective.PolicyID != "postgres-policy" || effective.Version != 7 || !effective.Published {
		t.Fatalf("effective policy after reopen = %+v, %v", effective, ok)
	}
	audits := reopened.Store.ListPolicyAudits("default", "postgres-policy")
	if len(audits) != 1 || audits[0].Actor != "tester" || audits[0].AssignmentID != assignment.AssignmentID {
		t.Fatalf("policy audits after reopen = %+v", audits)
	}
	if incidents := reopened.Store.ListIncidents(pgSelector("pg-policy")); len(incidents) != 0 {
		t.Fatalf("incidents persisted in postgres = %+v", incidents)
	}
}

func TestOpenPostgresBacksManagerIngestQueryPolicyAndIncidentAPI(t *testing.T) {
	fakeSetExecError(nil)
	fakeSetSnapshot(nil)
	result, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("Open(postgres) error = %v", err)
	}
	server := managerapi.NewServer(result.Store)
	handler := authenticatedManagerHandler(server.Handler())
	batch := backendDataBatch("pg-api-batch-1", "agent-pg-api", "host-pg-api",
		[]*eventv1.CanonicalEvent{{
			Id:       "ev-pg-api",
			Labels:   pgLabels("pg-api"),
			Behavior: "process.exec",
			AgentId:  "agent-pg-api",
			HostId:   "host-pg-api",
		}},
		[]*signalv1.Signal{
			postgresEndpointSignal("sig-pg-web", "pg-api", "web_runtime_spawns_shell", "lin-pg", false, postgresProcess("process:p-web")),
			postgresEndpointSignal("sig-pg-drop", "pg-api", "payload_dropped", "lin-pg", false, postgresFile("/dev/shm/x.sh")),
			postgresEndpointSignal("sig-pg-c2", "pg-api", "reverse_shell_pattern", "lin-pg", true, postgresProcess("process:p-bash"), postgresSocket("10.66.0.99:443")),
		})
	acceptDataBatch(t, result.Store, batch)
	assertGetContains(t, handler, "/api/v1/events?label=scenario=pg-api", `"id":"ev-pg-api"`)
	assertGetContains(t, handler, "/api/v1/signals?label=scenario=pg-api&layer=endpoint", `"id":"sig-pg-c2"`)

	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "pg-api-policy"
	policy.Version = 11
	policy.Published = false
	postJSON(t, handler, "/api/v1/policies?actor=pg-api-test", policy, http.StatusOK)
	postJSON(t, handler, "/api/v1/policy-publish", map[string]any{
		"tenant_id": "default", "policy_id": "pg-api-policy", "version": 11, "published": true, "actor": "publisher",
	}, http.StatusOK)
	postJSON(t, handler, "/api/v1/policy-assignments", map[string]any{
		"tenant_id": "default", "agent_id": "agent-pg-api", "policy_id": "pg-api-policy", "policy_version": 11, "actor": "operator",
	}, http.StatusOK)
	assertGetContains(t, handler, "/api/v1/effective-policy?tenant_id=default&agent_id=agent-pg-api", `"policy_id":"pg-api-policy"`)

	reopened, err := Open(context.Background(), Options{
		Kind:           KindPostgres,
		PostgresDriver: fakeDriverName,
		PostgresDSN:    "test-dsn",
	})
	if err != nil {
		t.Fatalf("reopen postgres error = %v", err)
	}
	reopenedHandler := authenticatedManagerHandler(managerapi.NewServer(reopened.Store).Handler())
	// Telemetry reports are not persisted in the relational backend.
	assertGetContains(t, reopenedHandler, "/api/v1/effective-policy?tenant_id=default&agent_id=agent-pg-api", `"policy_id":"pg-api-policy"`)
	assertGetContains(t, reopenedHandler, "/api/v1/policy-audit?tenant_id=default&policy_id=pg-api-policy", `"actor":"backend-admin"`)
}

func authenticatedManagerHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := managerauth.Principal{Subject: "backend-admin", TenantID: "default", Roles: []string{"admin"}}
		next.ServeHTTP(w, r.WithContext(managerauth.WithPrincipal(r.Context(), principal)))
	})
}

func TestOpenPostgresValidatesConfigAndWrapsMigrationError(t *testing.T) {
	if _, err := Open(context.Background(), Options{Kind: KindPostgres}); err == nil || !strings.Contains(err.Error(), "postgres driver is required") {
		t.Fatalf("missing driver error = %v", err)
	}
	if _, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName}); err == nil || !strings.Contains(err.Error(), "postgres dsn is required") {
		t.Fatalf("missing dsn error = %v", err)
	}
	fakeSetExecError(errors.New("boom"))
	if _, err := Open(context.Background(), Options{Kind: KindPostgres, PostgresDriver: fakeDriverName, PostgresDSN: "test-dsn"}); err == nil || !strings.Contains(err.Error(), "postgres schema migration") {
		t.Fatalf("migration error = %v", err)
	}
}

func backendDataBatch(batchID, agentID, hostID string, events []*eventv1.CanonicalEvent, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	batch := &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{
			BatchId:  batchID,
			AgentId:  agentID,
			HostId:   hostID,
			TenantId: "default",
		},
	}
	for i, event := range events {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{Sequence: uint64(i + 1), Event: event})
	}
	for i, signal := range signals {
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{Sequence: uint64(i + 1), Signal: signal})
	}
	return batch
}

func acceptDataBatch(t *testing.T, st *store.Store, batch *dataplanev1.DataBatch) {
	t.Helper()
	result, err := ingestworker.NewProcessor(st, nil).Process(context.Background(), batch)
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Duplicate {
		t.Fatalf("data batch rejected: %+v", result)
	}
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, wantStatus int) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(data)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("POST %s status = %d body=%s", path, rec.Code, rec.Body.String())
	}
}

func assertGetContains(t *testing.T, handler http.Handler, path string, want string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d body=%s", path, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("GET %s missing %s: %s", path, want, rec.Body.String())
	}
}

func postgresEndpointSignal(id, scenario, name, lineage string, terminal bool, entities ...*signalv1.EntityRef) *signalv1.Signal {
	return &signalv1.Signal{
		Id:           id,
		Name:         name,
		Where:        signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		BaseRisk:     50,
		GlobalRarity: 1,
		LineageId:    lineage,
		Terminal:     terminal,
		Entities:     entities,
		Labels:       pgLabels(scenario),
	}
}

func pgSelector(scenario string) store.LabelSelector {
	return store.LabelSelector{"scenario": scenario}
}

func pgLabels(scenario string) map[string]string {
	return map[string]string{"scenario": scenario}
}

func postgresProcess(key string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "process", Key: key, Role: "subject"}
}

func postgresFile(path string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "file", Key: "file:" + path, Role: "object"}
}

func postgresSocket(dst string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "socket", Key: "socket:" + dst, Role: "object"}
}

func TestOpenRejectsUnknownBackend(t *testing.T) {
	if _, err := Open(context.Background(), Options{Kind: "other"}); err == nil || !strings.Contains(err.Error(), "unknown store backend") {
		t.Fatalf("unknown backend error = %v", err)
	}
}

const fakeDriverName = "sysarmor-backend-postgres-test"

func init() {
	sql.Register(fakeDriverName, fakeDriver{})
}

var fakeState struct {
	sync.Mutex
	lastQuery          string
	execLog            []string
	execErr            error
	execErrQuery       string
	zeroRowsQuery      string
	snapshot           []byte
	eventRows          [][]byte
	signalRows         [][]byte
	incidentRows       [][]byte
	responseRows       [][]driver.Value
	policyRows         [][]byte
	assignmentRows     [][]byte
	policyAuditRows    [][]byte
	controlCommandRows [][]byte
	telemetryBatches   map[string]fakeTelemetryBatch
	metricsRows        map[string][]byte
	closeN             int
	commitN            int
	rollbackN          int
}

type fakeTelemetryBatch struct {
	status  string
	expired bool
}

func fakeSetExecError(err error) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.lastQuery = ""
	fakeState.execLog = nil
	fakeState.execErr = err
	fakeState.execErrQuery = ""
	fakeState.zeroRowsQuery = ""
	fakeState.eventRows = nil
	fakeState.signalRows = nil
	fakeState.incidentRows = nil
	fakeState.responseRows = nil
	fakeState.policyRows = nil
	fakeState.assignmentRows = nil
	fakeState.policyAuditRows = nil
	fakeState.controlCommandRows = nil
	fakeState.telemetryBatches = map[string]fakeTelemetryBatch{}
	fakeState.metricsRows = map[string][]byte{}
	fakeState.closeN = 0
	fakeState.commitN = 0
	fakeState.rollbackN = 0
}

func fakeReturnZeroRowsContaining(query string) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.lastQuery = ""
	fakeState.execLog = nil
	fakeState.execErr = nil
	fakeState.execErrQuery = ""
	fakeState.zeroRowsQuery = query
	fakeState.commitN = 0
	fakeState.rollbackN = 0
}

func fakeFailExecContaining(query string, err error) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.lastQuery = ""
	fakeState.execLog = nil
	fakeState.execErr = err
	fakeState.execErrQuery = query
	fakeState.commitN = 0
	fakeState.rollbackN = 0
}

func fakeTransactionCounts() (int, int) {
	fakeState.Lock()
	defer fakeState.Unlock()
	return fakeState.commitN, fakeState.rollbackN
}

func fakeClearExecLog() {
	fakeState.Lock()
	fakeState.lastQuery = ""
	fakeState.execLog = nil
	fakeState.Unlock()
}

func fakeSetSnapshot(data []byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.snapshot = data
}

func fakeSetEventRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.eventRows = nil
	for _, row := range rows {
		fakeState.eventRows = append(fakeState.eventRows, append([]byte(nil), row...))
	}
}

func fakeSetSignalRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.signalRows = nil
	for _, row := range rows {
		fakeState.signalRows = append(fakeState.signalRows, append([]byte(nil), row...))
	}
}

func fakeSetIncidentRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.incidentRows = nil
	for _, row := range rows {
		fakeState.incidentRows = append(fakeState.incidentRows, append([]byte(nil), row...))
	}
}

func fakeSetResponseRows(values ...driver.Value) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.responseRows = nil
	for i := 0; i < len(values); i += 2 {
		command := cloneDriverBytes(values[i])
		var ack driver.Value
		if i+1 < len(values) {
			ack = cloneDriverBytes(values[i+1])
		}
		fakeState.responseRows = append(fakeState.responseRows, []driver.Value{command, ack})
	}
}

func fakeSetPolicyRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.policyRows = nil
	for _, row := range rows {
		fakeState.policyRows = append(fakeState.policyRows, append([]byte(nil), row...))
	}
}

func fakeSetAssignmentRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.assignmentRows = nil
	for _, row := range rows {
		fakeState.assignmentRows = append(fakeState.assignmentRows, append([]byte(nil), row...))
	}
}

func fakeSetControlCommandRows(rows ...[]byte) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.controlCommandRows = nil
	for _, row := range rows {
		fakeState.controlCommandRows = append(fakeState.controlCommandRows, append([]byte(nil), row...))
	}
}

func cloneDriverBytes(value driver.Value) driver.Value {
	switch data := value.(type) {
	case []byte:
		return append([]byte(nil), data...)
	case string:
		return []byte(data)
	default:
		return value
	}
}

func fakeLastQuery() string {
	fakeState.Lock()
	defer fakeState.Unlock()
	return fakeState.lastQuery
}

func fakeExecLog() string {
	fakeState.Lock()
	defer fakeState.Unlock()
	return strings.Join(fakeState.execLog, "\n")
}

func fakeCloseCount() int {
	fakeState.Lock()
	defer fakeState.Unlock()
	return fakeState.closeN
}

type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return fakeConn{}, nil
}

type fakeConn struct{}

func (fakeConn) Prepare(query string) (driver.Stmt, error) {
	return fakeStmt{query: query}, nil
}

func (fakeConn) Close() error {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.closeN++
	return nil
}

func (fakeConn) Begin() (driver.Tx, error) {
	return fakeTx{}, nil
}

type fakeStmt struct {
	query string
}

func (s fakeStmt) Close() error {
	return nil
}

func (s fakeStmt) NumInput() int {
	return -1
}

func (s fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), nil)
}

func (s fakeStmt) ExecContext(_ context.Context, args []driver.NamedValue) (driver.Result, error) {
	fakeState.Lock()
	defer fakeState.Unlock()
	fakeState.lastQuery = s.query
	fakeState.execLog = append(fakeState.execLog, s.query, fakeArgs(args))
	if fakeState.execErr != nil && (fakeState.execErrQuery == "" || strings.Contains(s.query, fakeState.execErrQuery)) {
		return nil, fakeState.execErr
	}
	if fakeState.zeroRowsQuery != "" && strings.Contains(s.query, fakeState.zeroRowsQuery) {
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(s.query, "INSERT INTO sysarmor_state") && len(args) >= 3 {
		switch data := args[2].Value.(type) {
		case []byte:
			fakeState.snapshot = append([]byte(nil), data...)
		case string:
			fakeState.snapshot = []byte(data)
		}
	}
	if strings.Contains(s.query, "INSERT INTO events") && len(args) >= 6 {
		switch data := args[5].Value.(type) {
		case []byte:
			upsertFakeEventRow(append([]byte(nil), data...))
		case string:
			upsertFakeEventRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO signals") && len(args) >= 8 {
		switch data := args[7].Value.(type) {
		case []byte:
			upsertFakeSignalRow(append([]byte(nil), data...))
		case string:
			upsertFakeSignalRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO incidents") && len(args) >= 6 {
		switch data := args[5].Value.(type) {
		case []byte:
			fakeState.incidentRows = append(fakeState.incidentRows, append([]byte(nil), data...))
		case string:
			fakeState.incidentRows = append(fakeState.incidentRows, []byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO response_audit") && len(args) >= 8 {
		command := cloneDriverBytes(args[7].Value)
		var ack driver.Value
		if len(args) >= 9 {
			ack = cloneDriverBytes(args[8].Value)
		}
		upsertFakeResponseRow(command, ack)
	}
	if strings.Contains(s.query, "INSERT INTO policies") && len(args) >= 7 {
		dataArg := args[len(args)-1].Value
		switch data := dataArg.(type) {
		case []byte:
			upsertFakePolicyRow(append([]byte(nil), data...))
		case string:
			upsertFakePolicyRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO policy_assignments") && len(args) >= 8 {
		dataArg := args[len(args)-1].Value
		switch data := dataArg.(type) {
		case []byte:
			upsertFakeAssignmentRow(append([]byte(nil), data...))
		case string:
			upsertFakeAssignmentRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO policy_audit") && len(args) >= 10 {
		dataArg := args[len(args)-1].Value
		switch data := dataArg.(type) {
		case []byte:
			upsertFakePolicyAuditRow(append([]byte(nil), data...))
		case string:
			upsertFakePolicyAuditRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO control_commands") && len(args) >= 15 {
		dataArg := args[len(args)-1].Value
		switch data := dataArg.(type) {
		case []byte:
			upsertFakeControlCommandRow(append([]byte(nil), data...))
		case string:
			upsertFakeControlCommandRow([]byte(data))
		}
	}
	if strings.Contains(s.query, "INSERT INTO telemetry_batches") && len(args) >= 3 {
		key := fmt.Sprint(args[0].Value) + "\x00" + fmt.Sprint(args[1].Value)
		fakeState.telemetryBatches[key] = fakeTelemetryBatch{status: "processing"}
	}
	if strings.Contains(s.query, "UPDATE telemetry_batches SET status = 'completed'") && len(args) >= 2 {
		key := fmt.Sprint(args[0].Value) + "\x00" + fmt.Sprint(args[1].Value)
		record := fakeState.telemetryBatches[key]
		record.status = "completed"
		fakeState.telemetryBatches[key] = record
	}
	if strings.Contains(s.query, "INSERT INTO metrics") && len(args) >= 2 {
		tenantID := fmt.Sprint(args[0].Value)
		dataIndex := len(args) - 1
		fakeState.metricsRows[tenantID] = append([]byte(nil), cloneDriverBytes(args[dataIndex].Value).([]byte)...)
	}
	return driver.RowsAffected(1), nil
}

func fakeArgs(args []driver.NamedValue) string {
	values := make([]string, 0, len(args))
	for _, arg := range args {
		switch value := arg.Value.(type) {
		case []byte:
			values = append(values, string(value))
		default:
			values = append(values, fmt.Sprint(value))
		}
	}
	return strings.Join(values, " ")
}

func upsertFakeResponseRow(command, ack driver.Value) {
	responseID := fakeResponseID(command)
	if responseID != "" {
		for i, row := range fakeState.responseRows {
			if fakeResponseID(row[0]) == responseID {
				if responseUpdatedAt(row[0]).After(responseUpdatedAt(command)) {
					return
				}
				fakeState.responseRows[i] = []driver.Value{command, ack}
				return
			}
		}
	}
	fakeState.responseRows = append(fakeState.responseRows, []driver.Value{command, ack})
}

func responseUpdatedAt(value driver.Value) time.Time {
	var raw []byte
	switch data := value.(type) {
	case []byte:
		raw = data
	case string:
		raw = []byte(data)
	}
	var cmd responsemodel.Command
	_ = json.Unmarshal(raw, &cmd)
	return cmd.UpdatedAt
}

func upsertFakeEventRow(row []byte) {
	var event eventv1.CanonicalEvent
	if err := protojson.Unmarshal(row, &event); err == nil && event.GetId() != "" {
		for i, existing := range fakeState.eventRows {
			var existingEvent eventv1.CanonicalEvent
			if err := protojson.Unmarshal(existing, &existingEvent); err == nil && existingEvent.GetId() == event.GetId() {
				fakeState.eventRows[i] = row
				return
			}
		}
	}
	fakeState.eventRows = append(fakeState.eventRows, row)
}

func upsertFakeSignalRow(row []byte) {
	var signal signalv1.Signal
	if err := protojson.Unmarshal(row, &signal); err == nil && signal.GetId() != "" {
		for i, existing := range fakeState.signalRows {
			var existingSignal signalv1.Signal
			if err := protojson.Unmarshal(existing, &existingSignal); err == nil && existingSignal.GetId() == signal.GetId() {
				fakeState.signalRows[i] = row
				return
			}
		}
	}
	fakeState.signalRows = append(fakeState.signalRows, row)
}

func fakeResponseID(value driver.Value) string {
	var raw []byte
	switch data := value.(type) {
	case []byte:
		raw = data
	case string:
		raw = []byte(data)
	default:
		return ""
	}
	var cmd responsemodel.Command
	if err := json.Unmarshal(raw, &cmd); err != nil {
		return ""
	}
	return cmd.ResponseID
}

func upsertFakePolicyRow(row []byte) {
	var policy policymodel.Policy
	if err := json.Unmarshal(row, &policy); err == nil && policy.PolicyID != "" {
		for i, existing := range fakeState.policyRows {
			var existingPolicy policymodel.Policy
			if err := json.Unmarshal(existing, &existingPolicy); err != nil {
				continue
			}
			if existingPolicy.TenantID == policy.TenantID && existingPolicy.PolicyID == policy.PolicyID && existingPolicy.Version == policy.Version {
				fakeState.policyRows[i] = row
				return
			}
		}
	}
	fakeState.policyRows = append(fakeState.policyRows, row)
}

func upsertFakeAssignmentRow(row []byte) {
	var assignment policymodel.Assignment
	if err := json.Unmarshal(row, &assignment); err == nil && assignment.AssignmentID != "" {
		for i, existing := range fakeState.assignmentRows {
			var existingAssignment policymodel.Assignment
			if err := json.Unmarshal(existing, &existingAssignment); err != nil {
				continue
			}
			if existingAssignment.TenantID == assignment.TenantID && existingAssignment.AssignmentID == assignment.AssignmentID {
				fakeState.assignmentRows[i] = row
				return
			}
		}
	}
	fakeState.assignmentRows = append(fakeState.assignmentRows, row)
}

func upsertFakePolicyAuditRow(row []byte) {
	var audit policymodel.AuditRecord
	if err := json.Unmarshal(row, &audit); err == nil && audit.AuditID != "" {
		for i, existing := range fakeState.policyAuditRows {
			var existingAudit policymodel.AuditRecord
			if err := json.Unmarshal(existing, &existingAudit); err == nil && existingAudit.TenantID == audit.TenantID && existingAudit.AuditID == audit.AuditID {
				fakeState.policyAuditRows[i] = row
				return
			}
		}
	}
	fakeState.policyAuditRows = append(fakeState.policyAuditRows, row)
}

func upsertFakeControlCommandRow(row []byte) {
	var cmd controlmodel.ControlCommand
	if err := json.Unmarshal(row, &cmd); err == nil && cmd.CommandID != "" {
		for i, existing := range fakeState.controlCommandRows {
			var existingCommand controlmodel.ControlCommand
			if err := json.Unmarshal(existing, &existingCommand); err == nil && existingCommand.TenantID == cmd.TenantID && existingCommand.CommandID == cmd.CommandID {
				if existingCommand.UpdatedAt.After(cmd.UpdatedAt) {
					return
				}
				fakeState.controlCommandRows[i] = row
				return
			}
		}
	}
	fakeState.controlCommandRows = append(fakeState.controlCommandRows, row)
}

func (s fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), nil)
}

func (s fakeStmt) QueryContext(_ context.Context, args []driver.NamedValue) (driver.Rows, error) {
	fakeState.Lock()
	defer fakeState.Unlock()
	if strings.Contains(s.query, "FROM telemetry_batches") && len(args) >= 2 {
		key := fmt.Sprint(args[0].Value) + "\x00" + fmt.Sprint(args[1].Value)
		if record, ok := fakeState.telemetryBatches[key]; ok {
			if strings.Contains(s.query, "SELECT status, lease_until") {
				return &fakeRows{cols: []string{"status", "expired"}, rows: [][]driver.Value{{record.status, record.expired}}}, nil
			}
			return &fakeRows{cols: []string{"status"}, rows: [][]driver.Value{{record.status}}}, nil
		}
		return &fakeRows{}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM metrics") && len(args) >= 1 {
		if data := fakeState.metricsRows[fmt.Sprint(args[0].Value)]; len(data) > 0 {
			return &fakeRows{cols: []string{"data"}, rows: [][]driver.Value{{append([]byte(nil), data...)}}}, nil
		}
		return &fakeRows{}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM sysarmor_state") && len(fakeState.snapshot) > 0 {
		return &fakeRows{cols: []string{"data"}, rows: [][]driver.Value{{append([]byte(nil), fakeState.snapshot...)}}}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM events") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM events") && len(fakeState.eventRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.eventRows))
		for _, row := range fakeState.eventRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM signals") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM signals") && len(fakeState.signalRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.signalRows))
		for _, row := range fakeState.signalRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM incidents") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM incidents") && len(fakeState.incidentRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.incidentRows))
		for _, row := range fakeState.incidentRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT command, ack FROM response_audit") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT command, ack FROM response_audit") && len(fakeState.responseRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.responseRows))
		for _, row := range fakeState.responseRows {
			rows = append(rows, append([]driver.Value(nil), row...))
		}
		return &fakeRows{cols: []string{"command", "ack"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM policies") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM policies") && len(fakeState.policyRows) > 0 {
		policyRows := filterPolicyRows(s.query, args, fakeState.policyRows)
		rows := make([][]driver.Value, 0, len(policyRows))
		for _, row := range policyRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM policy_assignments") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM policy_assignments") && len(fakeState.assignmentRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.assignmentRows))
		for _, row := range fakeState.assignmentRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM policy_audit") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM policy_audit") && len(fakeState.policyAuditRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.policyAuditRows))
		for _, row := range fakeState.policyAuditRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	if strings.Contains(s.query, "SELECT data FROM control_commands") {
		fakeState.lastQuery = s.query
	}
	if strings.Contains(s.query, "SELECT data FROM control_commands") && len(fakeState.controlCommandRows) > 0 {
		rows := make([][]driver.Value, 0, len(fakeState.controlCommandRows))
		for _, row := range fakeState.controlCommandRows {
			rows = append(rows, []driver.Value{append([]byte(nil), row...)})
		}
		return &fakeRows{cols: []string{"data"}, rows: rows}, nil
	}
	return &fakeRows{}, nil
}

func filterPolicyRows(query string, args []driver.NamedValue, rows [][]byte) [][]byte {
	if !strings.Contains(query, "policy_id = $2") {
		return rows
	}
	var policyID string
	var version uint64
	if len(args) >= 2 {
		policyID = fmt.Sprint(args[1].Value)
	}
	if len(args) >= 3 {
		switch value := args[2].Value.(type) {
		case int64:
			version = uint64(value)
		case uint64:
			version = value
		case int:
			version = uint64(value)
		default:
			if parsed, err := strconv.ParseUint(fmt.Sprint(value), 10, 64); err == nil {
				version = parsed
			}
		}
	}
	out := make([][]byte, 0, len(rows))
	for _, row := range rows {
		var policy policymodel.Policy
		if err := json.Unmarshal(row, &policy); err != nil {
			continue
		}
		if policy.PolicyID != policyID {
			continue
		}
		if version != 0 && policy.Version != version {
			continue
		}
		out = append(out, row)
	}
	return out
}

type fakeTx struct{}

func (fakeTx) Commit() error {
	fakeState.Lock()
	fakeState.commitN++
	fakeState.Unlock()
	return nil
}

func (fakeTx) Rollback() error {
	fakeState.Lock()
	fakeState.rollbackN++
	fakeState.Unlock()
	return nil
}

type fakeRows struct {
	cols   []string
	rows   [][]driver.Value
	cursor int
}

func (r *fakeRows) Columns() []string {
	return r.cols
}

func (*fakeRows) Close() error {
	return nil
}

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.cursor >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.cursor])
	r.cursor++
	return nil
}
