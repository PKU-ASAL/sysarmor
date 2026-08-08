package store

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"path/filepath"
	"testing"
	"time"
)

func TestCommitEnrollmentIssueIsBoundToOneKey(t *testing.T) {
	st := &Store{}
	created := st.CreateEnrollment(Enrollment{
		EnrollmentID: "enr-a", TenantID: "default", AgentID: "agent-a",
		TokenHash: "token-hash", GatewayAddr: "gateway:9444", Status: "active",
	})
	proposed := created
	proposed.IssuedCertificatePEM = "certificate-a"
	proposed.IssuedSerialNumber = "1"
	proposed.IssuedAt = time.Now().UTC()

	issued, result, err := st.CommitEnrollmentIssue("token-hash", "key-a", proposed, AgentCertificate{
		TenantID: "default", AgentID: "agent-a", SerialNumber: "1",
	})
	if err != nil || result != EnrollmentIssued || issued.IssuedKeySHA256 != "key-a" {
		t.Fatalf("first issue result=%q enrollment=%+v err=%v", result, issued, err)
	}
	replayed, result, err := st.CommitEnrollmentIssue("token-hash", "key-a", Enrollment{}, AgentCertificate{})
	if err != nil || result != EnrollmentIssueReplay || replayed.IssuedSerialNumber != "1" {
		t.Fatalf("replay result=%q enrollment=%+v err=%v", result, replayed, err)
	}
	if _, result, err = st.CommitEnrollmentIssue("token-hash", "key-b", Enrollment{}, AgentCertificate{}); err != nil || result != EnrollmentIssueConflict {
		t.Fatalf("different key result=%q err=%v", result, err)
	}
}

func TestConsumeEnrollmentBootstrapRotatesTokenOnce(t *testing.T) {
	st := &Store{}
	st.CreateEnrollment(Enrollment{
		EnrollmentID:       "enr-bootstrap",
		TenantID:           "default",
		AgentID:            "agent-a",
		TokenHash:          "old-enrollment-hash",
		BootstrapTokenHash: "bootstrap-hash",
		Status:             "active",
		ExpiresAt:          time.Now().UTC().Add(time.Hour),
	})
	fetchedAt := time.Now().UTC()
	consumed, ok, err := st.ConsumeEnrollmentBootstrap("bootstrap-hash", "new-enrollment-hash", "enr_...new", fetchedAt)
	if err != nil || !ok {
		t.Fatalf("first consume enrollment=%+v ok=%t err=%v", consumed, ok, err)
	}
	if consumed.TokenHash != "new-enrollment-hash" || !consumed.BootstrapFetchedAt.Equal(fetchedAt) {
		t.Fatalf("consumed enrollment=%+v", consumed)
	}
	if _, ok := st.GetEnrollmentByTokenHash("old-enrollment-hash"); ok {
		t.Fatal("old enrollment token remained valid")
	}
	if _, ok, err := st.ConsumeEnrollmentBootstrap("bootstrap-hash", "another-hash", "enr_...other", fetchedAt.Add(time.Second)); err != nil || ok {
		t.Fatalf("second consume ok=%t err=%v", ok, err)
	}
}

func TestListSignalsFiltersLabelsLayerAndTerminal(t *testing.T) {
	st := &Store{}
	st.AddSignal(&signalv1.Signal{
		Id:       "s1",
		Name:     "reverse_shell_pattern",
		Labels:   scenarioMap("apt-fileless-c2"),
		Where:    signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		Terminal: true,
	})
	st.AddSignal(&signalv1.Signal{
		Id:     "s2",
		Name:   "web_shell_chain",
		Labels: scenarioMap("apt-fileless-c2"),
		Where:  signalv1.SignalWhere_SIGNAL_WHERE_CLOUD,
	})
	st.AddSignal(&signalv1.Signal{
		Id:     "s3",
		Name:   "payload_dropped",
		Labels: scenarioMap("apt-staged-drop"),
		Where:  signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
	})

	got := st.ListSignals(scenarioLabels("apt-fileless-c2"), "endpoint", true)
	if len(got) != 1 || got[0].GetId() != "s1" {
		t.Fatalf("expected terminal endpoint signal s1, got %#v", got)
	}

	got = st.ListSignals(scenarioLabels("apt-fileless-c2"), "cloud", false)
	if len(got) != 1 || got[0].GetId() != "s2" {
		t.Fatalf("expected cloud signal s2, got %#v", got)
	}
}

func TestTenantMetricsAccumulateByCommittedBatch(t *testing.T) {
	st := &Store{}
	commitTestTelemetry(t, st, "default", "batch-1", Metrics{DataBatchesAppended: 1, EventsIngested: 2, SignalsEmitted: 4, TotalConvergenceLatencyMs: 12, LastConvergenceLatencyMs: 12, MaxConvergenceLatencyMs: 12})
	commitTestTelemetry(t, st, "default", "batch-2", Metrics{DataBatchesAppended: 1, EventsIngested: 1, SignalsEmitted: 1, TotalConvergenceLatencyMs: 4, LastConvergenceLatencyMs: 4, MaxConvergenceLatencyMs: 4})

	got := st.MetricsSnapshotForTenant("default")
	if got.DataBatchesAppended != 2 {
		t.Fatalf("data batches appended = %d, want 2", got.DataBatchesAppended)
	}
	if got.EventsIngested != 3 {
		t.Fatalf("events ingested = %d, want 3", got.EventsIngested)
	}
	if got.SignalsEmitted != 5 {
		t.Fatalf("signals emitted = %d, want 5", got.SignalsEmitted)
	}
	if got.LastConvergenceLatencyMs != 4 || got.MaxConvergenceLatencyMs != 12 {
		t.Fatalf("latency metrics = last %d max %d, want last 4 max 12", got.LastConvergenceLatencyMs, got.MaxConvergenceLatencyMs)
	}
	if got.AverageConvergenceLatency != 8 {
		t.Fatalf("average latency = %f, want 8", got.AverageConvergenceLatency)
	}
}

func commitTestTelemetry(t *testing.T, st *Store, tenantID, batchID string, metrics Metrics) {
	t.Helper()
	claim, token, err := st.ClaimTelemetryBatch(context.Background(), tenantID, batchID, time.Minute)
	if err != nil || claim != BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	if err := st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{TenantID: tenantID, BatchID: batchID, ClaimToken: token, Metrics: metrics}); err != nil {
		t.Fatal(err)
	}
}

func TestMergeMetricsAddsCountersAndRecomputesLatency(t *testing.T) {
	got := MergeMetrics(
		Metrics{DataBatchesAppended: 2, EventsIngested: 4, TotalConvergenceLatencyMs: 10, MaxConvergenceLatencyMs: 6},
		Metrics{DataBatchesAppended: 1, EventsIngested: 3, TotalConvergenceLatencyMs: 8, LastConvergenceLatencyMs: 8, MaxConvergenceLatencyMs: 8},
	)
	if got.DataBatchesAppended != 3 || got.EventsIngested != 7 || got.TotalConvergenceLatencyMs != 18 || got.MaxConvergenceLatencyMs != 8 || got.LastConvergenceLatencyMs != 8 || got.AverageConvergenceLatency != 6 {
		t.Fatalf("merged metrics = %+v", got)
	}
}

func TestTelemetryIdentityIsTenantScoped(t *testing.T) {
	st := &Store{}
	if !st.AddEvent(&eventv1.CanonicalEvent{Id: "shared-event", TenantId: "tenant-a"}) {
		t.Fatal("tenant-a event was not inserted")
	}
	if !st.AddEvent(&eventv1.CanonicalEvent{Id: "shared-event", TenantId: "tenant-b"}) {
		t.Fatal("tenant-b event collided with tenant-a")
	}
	if !st.AddIncident(&incidentv1.Incident{TenantId: "tenant-a", Summary: "shared incident"}) {
		t.Fatal("tenant-a incident was not inserted")
	}
	if !st.AddIncident(&incidentv1.Incident{TenantId: "tenant-b", Summary: "shared incident"}) {
		t.Fatal("tenant-b incident collided with tenant-a")
	}
	if len(st.ListEvents(nil, "")) != 2 || len(st.ListIncidents(nil)) != 2 {
		t.Fatalf("events=%d incidents=%d", len(st.ListEvents(nil, "")), len(st.ListIncidents(nil)))
	}
}

func TestGetSignalForTenantDoesNotCollideOnSharedID(t *testing.T) {
	st := &Store{}
	st.AddSignalForTenant("tenant-a", &signalv1.Signal{Id: "shared-signal", Name: "signal-a"})
	st.AddSignalForTenant("tenant-b", &signalv1.Signal{Id: "shared-signal", Name: "signal-b"})

	for tenantID, wantName := range map[string]string{"tenant-a": "signal-a", "tenant-b": "signal-b"} {
		got, ok := st.GetSignalForTenant(tenantID, "shared-signal")
		if !ok || got.GetName() != wantName {
			t.Fatalf("GetSignalForTenant(%q) = (%v, %v), want name %q", tenantID, got, ok, wantName)
		}
	}
}

func TestTenantTelemetryStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.AddSignalForTenant("tenant-a", &signalv1.Signal{Id: "signal-a"})
	baseline := rarity.Baseline{}
	baseline.Observe([]*signalv1.Signal{{Name: "signal-a"}})
	claim, token, claimErr := st.ClaimTelemetryBatch(context.Background(), "tenant-a", "batch-a", time.Minute)
	if claimErr != nil || claim != BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, claimErr)
	}
	if err := st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{TenantID: "tenant-a", BatchID: "batch-a", ClaimToken: token, Metrics: Metrics{DataBatchesAppended: 1, EventsIngested: 2}, Rarity: baseline}); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.ListSignalsForTenant("tenant-a", nil, "", false)) != 1 {
		t.Fatal("tenant signals were not restored")
	}
	if reloaded.MetricsSnapshotForTenant("tenant-a").EventsIngested != 2 {
		t.Fatal("tenant metrics were not restored")
	}
	if reloaded.RarityBaselineSnapshotForTenant("tenant-a").Count("", "signal-a") != 1 {
		t.Fatal("tenant rarity baseline was not restored")
	}
}

func TestEvidencePullbacksPersistAcrossStateExport(t *testing.T) {
	st := &Store{}
	st.CreateEvidencePullback(controlmodel.EvidencePullbackRequest{
		RequestID:  "evpb-a",
		TenantID:   "default",
		AgentID:    "agent-a",
		IncidentID: "inc-a",
		Target:     "process:p1",
	})
	state, err := st.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored := &Store{}
	if err := restored.ImportState(state); err != nil {
		t.Fatal(err)
	}
	got := restored.PendingEvidencePullbacks("default", "agent-a")
	if len(got) != 1 {
		t.Fatalf("pullbacks = %+v", got)
	}
	if got[0].RequestID != "evpb-a" || got[0].Status != controlmodel.EvidencePullbackStatusPending {
		t.Fatalf("pullback = %+v", got[0])
	}
}

func TestControlCommandsPersistAndAck(t *testing.T) {
	st := &Store{}
	if _, err := st.CreateControlCommand(controlmodel.ControlCommand{
		CommandID:   "ctrl-a",
		TenantID:    "default",
		AgentID:     "agent-a",
		Type:        controlmodel.ControlCommandTypeContentUpdate,
		PayloadJSON: []byte(`{"kind":"iocpack"}`),
		Actor:       "operator",
		Reason:      "hot update",
	}); err != nil {
		t.Fatal(err)
	}
	if got := st.PendingControlCommands("default", "agent-a"); len(got) != 1 || got[0].CommandID != "ctrl-a" {
		t.Fatalf("pending commands = %+v", got)
	}
	if cmd, ok := st.MarkControlCommandSent("ctrl-a", "default", "agent-a", time.Unix(10, 0).UTC()); !ok || cmd.Status != controlmodel.ControlCommandStatusSent || cmd.SentAt.IsZero() || cmd.LastSentAt.IsZero() || cmd.AttemptCount != 1 {
		t.Fatalf("sent command = %+v ok=%t", cmd, ok)
	}
	if cmd, ok, err := st.AckControlCommand(controlmodel.ControlCommandAck{
		CommandID:  "ctrl-a",
		TenantID:   "default",
		AgentID:    "agent-a",
		Status:     "rejected",
		Message:    "bad content",
		ObservedAt: time.Unix(20, 0).UTC(),
	}); err != nil || !ok || cmd.Status != controlmodel.ControlCommandStatusRejected || cmd.Error != "bad content" || cmd.AckedAt.IsZero() {
		t.Fatalf("acked command = %+v ok=%t err=%v", cmd, ok, err)
	}
	if got := st.PendingControlCommands("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending after ack = %+v", got)
	}
	state, err := st.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored := &Store{}
	if err := restored.ImportState(state); err != nil {
		t.Fatal(err)
	}
	got := restored.ListControlCommands("default", "agent-a", controlmodel.ControlCommandTypeContentUpdate)
	if len(got) != 1 || got[0].CommandID != "ctrl-a" || got[0].Status != controlmodel.ControlCommandStatusRejected {
		t.Fatalf("restored commands = %+v", got)
	}
}

func TestControlCommandLifecycleActions(t *testing.T) {
	st := &Store{}
	if _, err := st.CreateControlCommand(controlmodel.ControlCommand{
		CommandID:   "ctrl-life",
		TenantID:    "default",
		AgentID:     "agent-a",
		Type:        controlmodel.ControlCommandTypePolicyUpdate,
		PayloadJSON: []byte(`{"policy_id":"p1","version":1}`),
	}); err != nil {
		t.Fatal(err)
	}
	if cmd, ok := st.CancelControlCommand("ctrl-life", "default", "agent-a", "operator", "bad rollout"); !ok || cmd.Status != controlmodel.ControlCommandStatusCanceled || cmd.CanceledAt.IsZero() || cmd.Actor != "operator" || cmd.Error != "bad rollout" {
		t.Fatalf("cancel command = %+v ok=%t", cmd, ok)
	}
	if got := st.PendingControlCommands("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending after cancel = %+v", got)
	}
	if cmd, ok := st.RetryControlCommand("ctrl-life", "default", "agent-a", "operator", "retry rollout"); !ok || cmd.Status != controlmodel.ControlCommandStatusPending || !cmd.CanceledAt.IsZero() || cmd.Reason != "retry rollout" || cmd.Error != "" {
		t.Fatalf("retry command = %+v ok=%t", cmd, ok)
	}
	if got := st.PendingControlCommands("default", "agent-a"); len(got) != 1 || got[0].CommandID != "ctrl-life" {
		t.Fatalf("pending after retry = %+v", got)
	}
	if cmd, ok := st.ExpireControlCommand("ctrl-life", "default", "agent-a", "ttl elapsed"); !ok || cmd.Status != controlmodel.ControlCommandStatusExpired || cmd.ExpiredAt.IsZero() || cmd.Error != "ttl elapsed" {
		t.Fatalf("expire command = %+v ok=%t", cmd, ok)
	}
	if got := st.PendingControlCommands("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending after expire = %+v", got)
	}
}

func TestApproveResponseMovesPendingApprovalToPending(t *testing.T) {
	st := &Store{}
	if _, err := st.CreateResponse(responsemodel.Command{
		ResponseID:       "resp-approve",
		TenantID:         "default",
		AgentID:          "agent-a",
		Action:           "collect",
		Mode:             "observe",
		Status:           "pending_approval",
		ApprovalRequired: true,
		ApprovalStatus:   "required",
	}); err != nil {
		t.Fatal(err)
	}
	if got := st.PendingResponses("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending before approval = %+v", got)
	}
	cmd, ok := st.ApproveResponse("default", "agent-a", "resp-approve", true, "analyst", "", "approved for collection")
	if !ok {
		t.Fatal("ApproveResponse ok = false")
	}
	if cmd.Status != "pending" || cmd.ApprovalStatus != "approved" || cmd.ApprovedBy != "analyst" || cmd.ApprovedAt.IsZero() {
		t.Fatalf("approved command = %+v", cmd)
	}
	if got := st.PendingResponses("default", "agent-a"); len(got) != 1 || got[0].ResponseID != "resp-approve" {
		t.Fatalf("pending after approval = %+v", got)
	}
}

func TestApproveResponseRejectsNonApprovalCommand(t *testing.T) {
	st := &Store{}
	if _, err := st.CreateResponse(responsemodel.Command{
		ResponseID: "resp-denied",
		TenantID:   "default",
		AgentID:    "agent-a",
		Action:     "kill",
		Mode:       "observe",
		Status:     "denied",
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.ApproveResponse("default", "agent-a", "resp-denied", true, "analyst", "", "no bypass"); ok {
		t.Fatal("ApproveResponse ok = true for non-approval command")
	}
	audits := st.ListResponses("default", "agent-a")
	if len(audits) != 1 || audits[0].Command.Status != "denied" {
		t.Fatalf("audits = %+v", audits)
	}
}

func TestApproveResponseRequiresThresholdAndAllowedRole(t *testing.T) {
	st := &Store{}
	if _, err := st.CreateResponse(responsemodel.Command{
		ResponseID:        "resp-multi-approve",
		TenantID:          "default",
		AgentID:           "agent-a",
		Action:            "collect",
		Mode:              "observe",
		Status:            "pending_approval",
		ApprovalRequired:  true,
		ApprovalStatus:    "required",
		ApprovalThreshold: 2,
		ApprovalRoles:     []string{"responder", "security_admin"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.ApproveResponse("default", "agent-a", "resp-multi-approve", true, "observer", "viewer", "wrong role"); ok {
		t.Fatal("ApproveResponse ok = true for wrong role")
	}
	cmd, ok := st.ApproveResponse("default", "agent-a", "resp-multi-approve", true, "responder-a", "responder", "first approval")
	if !ok {
		t.Fatal("first ApproveResponse ok = false")
	}
	if cmd.Status != "pending_approval" || cmd.ApprovalStatus != "partial" || len(cmd.Approvals) != 1 {
		t.Fatalf("after first approval = %+v", cmd)
	}
	if got := st.PendingResponses("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending after partial approval = %+v", got)
	}
	cmd, ok = st.ApproveResponse("default", "agent-a", "resp-multi-approve", true, "security-b", "security_admin", "second approval")
	if !ok {
		t.Fatal("second ApproveResponse ok = false")
	}
	if cmd.Status != "pending" || cmd.ApprovalStatus != "approved" || len(cmd.Approvals) != 2 || cmd.ApprovedBy != "security-b" {
		t.Fatalf("after second approval = %+v", cmd)
	}
	if got := st.PendingResponses("default", "agent-a"); len(got) != 1 || got[0].ResponseID != "resp-multi-approve" {
		t.Fatalf("pending after threshold approval = %+v", got)
	}
}

func TestCompleteEvidencePullbackUpdatesStatus(t *testing.T) {
	st := &Store{}
	st.CreateEvidencePullback(controlmodel.EvidencePullbackRequest{
		RequestID: "evpb-a",
		TenantID:  "default",
		AgentID:   "agent-a",
	})
	req, ok := st.CompleteEvidencePullback(controlmodel.EvidencePullbackResult{
		RequestID: "evpb-a",
		TenantID:  "default",
		AgentID:   "agent-a",
		OK:        true,
		Message:   "collected",
	})
	if !ok {
		t.Fatal("CompleteEvidencePullback ok = false")
	}
	if req.Status != controlmodel.EvidencePullbackStatusCompleted || !req.ResultOK || req.Result != "collected" || req.CompletedAt.IsZero() {
		t.Fatalf("completed request = %+v", req)
	}
	if got := st.PendingEvidencePullbacks("default", "agent-a"); len(got) != 0 {
		t.Fatalf("pending after completion = %+v", got)
	}
}

func TestListIncidentsFiltersLabels(t *testing.T) {
	st := &Store{}
	st.AddIncident(&incidentv1.Incident{Id: "i1", Labels: scenarioMap("apt-fileless-c2")})
	st.AddIncident(&incidentv1.Incident{Id: "i2", Labels: scenarioMap("benign-ci-noise")})

	got := st.ListIncidents(scenarioLabels("apt-fileless-c2"))
	if len(got) != 1 || got[0].GetId() != "i1" {
		t.Fatalf("expected incident i1, got %#v", got)
	}
}

func TestStoreInfoReportsBackendAndVersions(t *testing.T) {
	memory := (&Store{}).Info()
	if memory.Backend != "memory" || memory.Path != "" || memory.StateVersion == 0 || memory.PostgresSchema == 0 {
		t.Fatalf("memory store info = %+v", memory)
	}
	path := filepath.Join(t.TempDir(), "store.json")
	fileStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	file := fileStore.Info()
	if file.Backend != "file" || file.Path != path || file.MigrationVersion != FileStoreStateVersion {
		t.Fatalf("file store info = %+v", file)
	}
}

func TestIncidentEvidenceAttachPersistsAcrossUpsert(t *testing.T) {
	st := &Store{}
	sig := testSignal("sig-a", "a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "reverse_shell_pattern", "lin-a", "process:p-bash")
	inc := &incidentv1.Incident{
		Id:                  "inc-a",
		Labels:              scenarioMap("a"),
		Summary:             "same story",
		LineageIds:          []string{"lin-a"},
		Evidence:            &incidentv1.EvidenceSubgraph{Nodes: []*incidentv1.GraphNode{{Id: "process:p-bash", Kind: "process"}}},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity+causal-topk"},
		ContributingSignals: []*signalv1.Signal{sig},
	}
	st.AddIncident(inc)
	if _, ok := st.AttachIncidentEvidence("", scenarioLabels("a"), &incidentv1.EvidenceSubgraph{
		Nodes: []*incidentv1.GraphNode{
			{Id: "user:root", Kind: "user", Label: "root"},
			{Id: "process:p-bash", Kind: "process"},
		},
		Edges: []*incidentv1.GraphEdge{{From: "process:p-bash", To: "user:root", Kind: "ran_as"}},
	}); !ok {
		t.Fatal("AttachIncidentEvidence ok = false")
	}
	st.AddIncident(&incidentv1.Incident{
		Id:                  "inc-b",
		Labels:              scenarioMap("a"),
		Summary:             "same story",
		LineageIds:          []string{"lin-a"},
		Evidence:            &incidentv1.EvidenceSubgraph{Nodes: []*incidentv1.GraphNode{{Id: "process:p-bash", Kind: "process"}}},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity+causal-topk"},
		ContributingSignals: []*signalv1.Signal{sig},
	})
	got := st.ListIncidents(scenarioLabels("a"))[0].GetEvidence()
	if len(got.GetNodes()) != 2 {
		t.Fatalf("nodes after attach/upsert = %d, want 2: %+v", len(got.GetNodes()), got.GetNodes())
	}
	if len(got.GetEdges()) != 1 || got.GetEdges()[0].GetKind() != "ran_as" {
		t.Fatalf("edges after attach/upsert = %+v", got.GetEdges())
	}
}

func TestMergeIncidentsCombinesEvidenceAndRemovesSource(t *testing.T) {
	st := &Store{}
	st.AddIncident(&incidentv1.Incident{
		Id:         "inc-a",
		Labels:     scenarioMap("a"),
		Summary:    "target",
		Severity:   40,
		Mitre:      []string{"T1059"},
		LineageIds: []string{"lin-a"},
		Terminals:  []string{"process:p-a"},
		Evidence:   &incidentv1.EvidenceSubgraph{Nodes: []*incidentv1.GraphNode{{Id: "process:p-a", Kind: "process"}}},
		ContributingSignals: []*signalv1.Signal{
			testSignal("sig-a", "a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "payload_dropped", "lin-a", "file:/tmp/a"),
		},
	})
	st.AddIncident(&incidentv1.Incident{
		Id:         "inc-b",
		Labels:     scenarioMap("b"),
		Summary:    "source",
		Severity:   80,
		Mitre:      []string{"T1105"},
		LineageIds: []string{"lin-b"},
		Terminals:  []string{"process:p-b"},
		Evidence: &incidentv1.EvidenceSubgraph{
			Nodes: []*incidentv1.GraphNode{{Id: "process:p-b", Kind: "process"}},
			Edges: []*incidentv1.GraphEdge{{From: "process:p-a", To: "process:p-b", Kind: "related"}},
		},
		ContributingSignals: []*signalv1.Signal{
			testSignal("sig-b", "b", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "reverse_shell_pattern", "lin-b", "process:p-b"),
		},
	})
	merged, ok := st.MergeIncidents("inc-a", "inc-b")
	if !ok {
		t.Fatal("MergeIncidents ok = false")
	}
	if merged.GetSeverity() != 80 {
		t.Fatalf("severity = %d, want 80", merged.GetSeverity())
	}
	if len(merged.GetLineageIds()) != 2 || len(merged.GetTerminals()) != 2 || len(merged.GetMitre()) != 2 {
		t.Fatalf("merged fields incomplete: lineage=%v terminals=%v mitre=%v", merged.GetLineageIds(), merged.GetTerminals(), merged.GetMitre())
	}
	if len(merged.GetEvidence().GetNodes()) != 2 || len(merged.GetEvidence().GetEdges()) != 1 {
		t.Fatalf("merged evidence = %+v", merged.GetEvidence())
	}
	if len(merged.GetContributingSignals()) != 2 {
		t.Fatalf("contributing signals = %d, want 2", len(merged.GetContributingSignals()))
	}
	if got := st.ListIncidents(nil); len(got) != 1 || got[0].GetId() != "inc-a" {
		t.Fatalf("incidents after merge = %+v", got)
	}
}

func TestUpsertsDuplicateEventsSignalsAndIncidents(t *testing.T) {
	st := &Store{}
	if inserted := st.AddEvent(testEvent("ev-1", "a")); !inserted {
		t.Fatal("first AddEvent inserted = false")
	}
	if inserted := st.AddEvent(testEvent("ev-1", "a")); inserted {
		t.Fatal("duplicate AddEvent inserted = true")
	}
	if got := st.ListEvents(scenarioLabels("a"), ""); len(got) != 1 {
		t.Fatalf("events after duplicate upsert = %d, want 1", len(got))
	}

	sig := testSignal("sig-a", "a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "payload_dropped", "lin-a", "file:/tmp/x")
	if inserted := st.AddSignal(sig); !inserted {
		t.Fatal("first AddSignal inserted = false")
	}
	if inserted := st.AddSignal(testSignal("sig-b", "a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "payload_dropped", "lin-a", "file:/tmp/x")); inserted {
		t.Fatal("duplicate AddSignal inserted = true")
	}
	st.AddSignal(testSignal("sig-c", "a", signalv1.SignalWhere_SIGNAL_WHERE_CLOUD, "payload_dropped", "lin-a", "file:/tmp/x"))
	st.AddSignal(testSignal("sig-d", "a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "payload_dropped", "lin-a", "file:/tmp/y"))
	if got := st.ListSignals(scenarioLabels("a"), "", false); len(got) != 3 {
		t.Fatalf("signals after semantic duplicate upsert = %d, want 3", len(got))
	}

	inc := &incidentv1.Incident{
		Id:                  "inc-a",
		Labels:              scenarioMap("a"),
		Summary:             "same story",
		LineageIds:          []string{"lin-a", "lin-b"},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity+causal-topk"},
		ContributingSignals: []*signalv1.Signal{sig},
	}
	if inserted := st.AddIncident(inc); !inserted {
		t.Fatal("first AddIncident inserted = false")
	}
	if inserted := st.AddIncident(&incidentv1.Incident{
		Id:                  "inc-b",
		Labels:              scenarioMap("a"),
		Summary:             "same story",
		LineageIds:          []string{"lin-b", "lin-a"},
		Converge:            &incidentv1.ConvergeTrace{Method: "rarity+causal-topk"},
		ContributingSignals: []*signalv1.Signal{sig},
	}); inserted {
		t.Fatal("duplicate AddIncident inserted = true")
	}
	if got := st.ListIncidents(scenarioLabels("a")); len(got) != 1 {
		t.Fatalf("incidents after semantic duplicate upsert = %d, want 1", len(got))
	}
}

func TestAddAgentSeparatesTenants(t *testing.T) {
	st := &Store{}
	st.AddAgent(AgentIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "tenant-a"})
	st.AddAgent(AgentIdentity{AgentID: "agent-a", HostID: "host-b", TenantID: "tenant-b"})
	st.AddAgent(AgentIdentity{AgentID: "agent-a", HostID: "host-a2", TenantID: "tenant-a"})
	agents := st.ListAgents()
	if len(agents) != 2 {
		t.Fatalf("agents = %d, want 2 tenant-scoped entries", len(agents))
	}
	for _, agent := range agents {
		if agent.TenantID == "tenant-a" && agent.HostID != "host-a2" {
			t.Fatalf("tenant-a agent was not updated: %+v", agent)
		}
	}
}

func TestBindAgentIdentityLocksCertificatePrincipal(t *testing.T) {
	st := &Store{}
	if err := st.BindAgentIdentity(AgentIdentity{
		AgentID:      "agent-a",
		TenantID:     "tenant-a",
		AuthType:     "mtls",
		CertIdentity: "spiffe://sysarmor.local/tenant/tenant-a/agent/agent-a",
	}); err != nil {
		t.Fatalf("BindAgentIdentity() error = %v", err)
	}
	st.AddAgent(AgentIdentity{AgentID: "agent-a", TenantID: "tenant-a", HostID: "host-a", Version: "v1"})
	agents := st.ListAgents()
	if len(agents) != 1 || agents[0].CertIdentity == "" || agents[0].AuthType != "mtls" || agents[0].HostID != "host-a" {
		t.Fatalf("agents = %+v, want preserved mTLS binding with updated host", agents)
	}
	err := st.BindAgentIdentity(AgentIdentity{
		AgentID:      "agent-a",
		TenantID:     "tenant-a",
		AuthType:     "mtls",
		CertIdentity: "spiffe://sysarmor.local/tenant/tenant-a/agent/agent-b",
	})
	if err == nil {
		t.Fatal("BindAgentIdentity() mismatched cert identity succeeded")
	}
}

func TestAgentHealthUpsertAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAgentHealth(agenthealth.AgentHealth{
		AgentID:    "agent-a",
		HostID:     "host-a",
		TenantID:   "default",
		Scope:      agenthealth.RuntimeScope{Type: "container", Selector: "abc123"},
		Status:     "ok",
		ObservedAt: time.Now().UTC(),
		Capability: agenthealth.SensorCapability{Backend: "fake", KernelRelease: "test-kernel", BTFAvailable: true, BPFFSAvailable: true},
		Sensor:     agenthealth.SensorHealth{Backend: "fake", Running: true, EventsSeen: 1},
	})
	st.UpsertAgentHealth(agenthealth.AgentHealth{
		AgentID:    "agent-a",
		HostID:     "host-a",
		TenantID:   "default",
		Scope:      agenthealth.RuntimeScope{Type: "container", Selector: "abc123"},
		Status:     "degraded",
		ObservedAt: time.Now().UTC(),
		Capability: agenthealth.SensorCapability{Backend: "fake", KernelRelease: "test-kernel", BTFAvailable: true, BPFFSAvailable: true},
		Sensor:     agenthealth.SensorHealth{Backend: "fake", Running: true, EventsSeen: 2},
	})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.GetAgentHealth("default", "agent-a")
	if !ok {
		t.Fatal("agent health not found")
	}
	if got.Status != "degraded" || got.Sensor.EventsSeen != 2 || got.Scope.Type != "container" || got.Scope.Selector != "abc123" || got.Capability.KernelRelease != "test-kernel" || !got.Capability.BTFAvailable || !got.Capability.BPFFSAvailable {
		t.Fatalf("health = %+v", got)
	}
	if got := reloaded.ListAgentHealth(); len(got) != 1 {
		t.Fatalf("health list len = %d, want 1", len(got))
	}
}

func TestExportImportStateRoundTrip(t *testing.T) {
	st := &Store{}
	st.AddAgent(AgentIdentity{AgentID: "agent-a", HostID: "host-a", TenantID: "default", Version: "test"})
	st.AddEvent(testEvent("ev-a", "scenario-a"))
	st.AddSignal(testSignal("sig-a", "scenario-a", signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT, "reverse_shell_pattern", "lin-a", "process:p-bash"))
	st.AddIncident(&incidentv1.Incident{Id: "inc-a", Labels: scenarioMap("scenario-a"), Summary: "incident-a"})
	st.UpsertAgentHealth(agenthealth.AgentHealth{AgentID: "agent-a", HostID: "host-a", TenantID: "default", Status: "ok"})
	st.RecordDataBatchAppend(AgentIdentity{AgentID: "agent-a", TenantID: "default"}, "batch-a", "http", time.Unix(10, 0).UTC())
	baseline := rarity.Baseline{}
	baseline.Observe([]*signalv1.Signal{{
		Name: "download_by_lolbin",
		Entities: []*signalv1.EntityRef{{
			Kind: "container",
			Key:  "checkout-api",
		}},
	}})
	claim, token, err := st.ClaimTelemetryBatch(context.Background(), "default", "telemetry-batch", time.Minute)
	if err != nil || claim != BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	if err := st.CommitTelemetryBatch(context.Background(), TelemetryBatchDelta{TenantID: "default", BatchID: "telemetry-batch", ClaimToken: token, Metrics: Metrics{DataBatchesAppended: 1, SignalsEmitted: 2}, Rarity: baseline}); err != nil {
		t.Fatal(err)
	}

	state, err := st.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	reloaded := &Store{}
	if err := reloaded.ImportState(state); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.ListAgents(); len(got) != 1 || got[0].AgentID != "agent-a" {
		t.Fatalf("agents after import = %+v", got)
	}
	if got := reloaded.ListEvents(scenarioLabels("scenario-a"), ""); len(got) != 1 || got[0].GetId() != "ev-a" {
		t.Fatalf("events after import = %+v", got)
	}
	if got := reloaded.ListSignals(scenarioLabels("scenario-a"), "endpoint", false); len(got) != 1 || got[0].GetId() != "sig-a" {
		t.Fatalf("signals after import = %+v", got)
	}
	if got := reloaded.ListIncidents(scenarioLabels("scenario-a")); len(got) != 1 || got[0].GetId() != "inc-a" {
		t.Fatalf("incidents after import = %+v", got)
	}
	if _, ok := reloaded.GetAgentHealth("default", "agent-a"); !ok {
		t.Fatal("agent health missing after import")
	}
	if got := reloaded.ListAgentSessions("default", "agent-a"); len(got) != 1 || got[0].LastAckCursor != "batch-a" {
		t.Fatalf("agent sessions after import = %+v", got)
	}
	if got := reloaded.MetricsSnapshotForTenant("default"); got.DataBatchesAppended != 1 || got.SignalsEmitted != 2 {
		t.Fatalf("metrics after import = %+v", got)
	}
	if got := reloaded.RarityBaselineSnapshotForTenant("default").Count("container:checkout-api", "download_by_lolbin"); got != 1 {
		t.Fatalf("rarity baseline after import = %d, want 1", got)
	}
}

func TestRecordDataBatchAppendUpdatesSessionCursor(t *testing.T) {
	st := &Store{}
	agent := AgentIdentity{AgentID: "agent-a", TenantID: "default"}
	first := st.RecordDataBatchAppend(agent, "batch-1", "http", time.Unix(10, 0).UTC())
	second := st.RecordDataBatchAppend(agent, "batch-2", "grpc", time.Unix(20, 0).UTC())
	if first.SessionID == "" || first.SessionID != second.SessionID {
		t.Fatalf("session ids = %q/%q", first.SessionID, second.SessionID)
	}
	sessions := st.ListAgentSessions("default", "agent-a")
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
	got := sessions[0]
	if got.StartedAt != first.StartedAt || got.LastSeenAt != second.LastSeenAt || got.LastAckCursor != "batch-2" || got.DataTransport != "grpc" {
		t.Fatalf("session after update = %+v", got)
	}
}

func TestAgentSessionLifecycle(t *testing.T) {
	st := &Store{}
	opened := st.RecordControlSessionOpen("default", "agent-control", "control", time.Unix(10, 0).UTC())
	if opened.Status != "open" || opened.ControlTransport != "control" || !opened.ClosedAt.IsZero() {
		t.Fatalf("opened session = %+v", opened)
	}
	seen := st.RecordAgentSessionSeen("default", "agent-control", time.Unix(20, 0).UTC())
	if seen.Status != "open" || !seen.LastSeenAt.Equal(time.Unix(20, 0).UTC()) {
		t.Fatalf("seen session = %+v", seen)
	}
	st.RecordDataBatchAppend(AgentIdentity{AgentID: "agent-control", TenantID: "default"}, "batch-grpc", "grpc", time.Unix(25, 0).UTC())
	closed := st.CloseAgentSession("default", "agent-control", time.Unix(30, 0).UTC())
	if closed.Status != "closed" || !closed.ClosedAt.Equal(time.Unix(30, 0).UTC()) || closed.LastAckCursor != "batch-grpc" {
		t.Fatalf("closed session = %+v", closed)
	}
	reopened := st.RecordControlSessionOpen("default", "agent-control", "control", time.Unix(40, 0).UTC())
	if reopened.Status != "open" || reopened.ControlTransport != "control" || !reopened.ClosedAt.IsZero() || reopened.LastAckCursor != "batch-grpc" {
		t.Fatalf("reopened session = %+v", reopened)
	}
}

func TestDeleteByLabels(t *testing.T) {
	st := &Store{}
	st.AddSignal(&signalv1.Signal{Id: "s1", Labels: scenarioMap("a")})
	st.AddSignal(&signalv1.Signal{Id: "s2", Labels: scenarioMap("b")})
	st.AddIncident(&incidentv1.Incident{Id: "i1", Labels: scenarioMap("a")})
	st.AddIncident(&incidentv1.Incident{Id: "i2", Labels: scenarioMap("b")})

	st.DeleteByLabels(scenarioLabels("a"))

	if got := st.ListSignals(scenarioLabels("a"), "", false); len(got) != 0 {
		t.Fatalf("signals for deleted scenario = %d, want 0", len(got))
	}
	if got := st.ListIncidents(scenarioLabels("a")); len(got) != 0 {
		t.Fatalf("incidents for deleted scenario = %d, want 0", len(got))
	}
	if got := st.ListSignals(scenarioLabels("b"), "", false); len(got) != 1 {
		t.Fatalf("signals for other scenario = %d, want 1", len(got))
	}
	if got := st.ListIncidents(scenarioLabels("b")); len(got) != 1 {
		t.Fatalf("incidents for other scenario = %d, want 1", len(got))
	}
}

func TestUpsertPolicyWithErrorReturnsBackendFailure(t *testing.T) {
	st := &Store{}
	st.AttachBackend(context.Background(), failingPolicyBackend{}, Info{Backend: "test"})

	_, err := st.UpsertPolicyWithError(policymodel.Policy{TenantID: "default", PolicyID: "policy-fail", Version: 1})
	if err == nil || !strings.Contains(err.Error(), "write policy") {
		t.Fatalf("UpsertPolicyWithError error = %v, want backend write failure", err)
	}
	if got := st.Policies; len(got) != 0 {
		t.Fatalf("policies after failed write = %+v, want rollback", got)
	}
}

func TestUpsertPolicyWithErrorPublishesOnlyAfterBackendCommit(t *testing.T) {
	backend := newOrderedPolicyBackend()
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-race", Version: 1, Mode: "old"}}}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})
	firstDone := make(chan error, 1)

	go func() {
		_, err := st.UpsertPolicyWithError(policymodel.Policy{TenantID: "default", PolicyID: "policy-race", Version: 1, Mode: "first"})
		firstDone <- err
	}()
	<-backend.firstStarted
	st.mu.RLock()
	got := st.Policies[0]
	st.mu.RUnlock()
	if got.Mode != "old" {
		t.Fatalf("policy before backend commit = %+v, want previous durable state", got)
	}
	close(backend.releaseFirst)
	if err := <-firstDone; err == nil {
		t.Fatal("UpsertPolicyWithError error = nil, want backend failure")
	}
}

func TestPublishPolicyBackendWriteDoesNotBlockStoreReads(t *testing.T) {
	backend := &blockingPolicyWriteBackend{started: make(chan struct{}), release: make(chan struct{})}
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-blocked", Version: 1}}}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})
	writeDone := make(chan error, 1)
	go func() {
		_, _, err := st.PublishPolicy("default", "policy-blocked", 1, true)
		writeDone <- err
	}()
	<-backend.started
	readDone := make(chan struct{})
	go func() {
		st.mu.RLock()
		st.mu.RUnlock()
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(100 * time.Millisecond):
		close(backend.release)
		<-writeDone
		t.Fatal("store read blocked by policy backend write")
	}
	close(backend.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("PublishPolicy error = %v", err)
	}
}

type blockingPolicyWriteBackend struct {
	Backend
	started chan struct{}
	release chan struct{}
}

func (b *blockingPolicyWriteBackend) WritePolicy(context.Context, policymodel.Policy) error {
	close(b.started)
	<-b.release
	return nil
}

type orderedPolicyBackend struct {
	Backend
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	releaseFirst chan struct{}
}

func newOrderedPolicyBackend() *orderedPolicyBackend {
	return &orderedPolicyBackend{firstStarted: make(chan struct{}), releaseFirst: make(chan struct{})}
}

func (b *orderedPolicyBackend) WritePolicy(context.Context, policymodel.Policy) error {
	b.mu.Lock()
	b.calls++
	call := b.calls
	b.mu.Unlock()
	if call == 1 {
		close(b.firstStarted)
		<-b.releaseFirst
		return errors.New("first write failed")
	}
	return nil
}

type failingPolicyBackend struct {
	Backend
}

func (failingPolicyBackend) WritePolicy(context.Context, policymodel.Policy) error {
	return errors.New("backend down")
}

func TestEnsureDefaultPolicyWithErrorPersistsManagerDefault(t *testing.T) {
	backend := &defaultPolicyBackend{}
	st := &Store{}
	st.AttachBackend(t.Context(), backend, Info{Backend: "test"})
	if err := st.EnsureDefaultPolicyWithError("default"); err != nil {
		t.Fatal(err)
	}
	if len(backend.writes) != 1 || !managerDefaultPolicyUsable(backend.writes[0]) {
		t.Fatalf("default policy writes = %+v", backend.writes)
	}
}

func TestEnsureDefaultPolicyWithErrorReturnsBackendFailure(t *testing.T) {
	backend := &defaultPolicyBackend{writeErr: errors.New("backend down")}
	st := &Store{}
	st.AttachBackend(t.Context(), backend, Info{Backend: "test"})
	err := st.EnsureDefaultPolicyWithError("default")
	if err == nil || !strings.Contains(err.Error(), "persist default policy") {
		t.Fatalf("EnsureDefaultPolicyWithError error = %v", err)
	}
}

type defaultPolicyBackend struct {
	Backend
	existing policymodel.Policy
	writes   []policymodel.Policy
	writeErr error
}

func (b *defaultPolicyBackend) GetPolicy(context.Context, string, string, uint64) (policymodel.Policy, bool, error) {
	return b.existing, b.existing.PolicyID != "", nil
}

func (b *defaultPolicyBackend) WritePolicy(_ context.Context, policy policymodel.Policy) error {
	if b.writeErr != nil {
		return b.writeErr
	}
	b.writes = append(b.writes, policy)
	return nil
}

func TestCreateResponseReturnsBackendFailure(t *testing.T) {
	st := &Store{}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "response"}, Info{Backend: "test"})

	_, err := st.CreateResponse(responsemodel.Command{ResponseID: "response-fail", TenantID: "default", AgentID: "agent-a"})
	if err == nil || !strings.Contains(err.Error(), "write response") {
		t.Fatalf("CreateResponse error = %v, want backend write failure", err)
	}
	if len(st.Responses) != 0 {
		t.Fatalf("responses after failed write = %+v, want unchanged", st.Responses)
	}
}

func TestCreateResponseReturnsFilePersistenceFailure(t *testing.T) {
	st := &Store{path: t.TempDir()}

	_, err := st.CreateResponse(responsemodel.Command{ResponseID: "response-fail", TenantID: "default", AgentID: "agent-a"})
	if err == nil || !strings.Contains(err.Error(), "write response") {
		t.Fatalf("CreateResponse error = %v, want file write failure", err)
	}
	if len(st.Responses) != 0 {
		t.Fatalf("responses after failed file write = %+v, want unchanged", st.Responses)
	}
}

func TestAckResponseReturnsFilePersistenceFailure(t *testing.T) {
	st := &Store{path: t.TempDir(), Responses: []responsemodel.Command{{ResponseID: "response-file", TenantID: "default", AgentID: "agent-a", Status: "pending"}}}
	_, ok, err := st.AckResponse(responsemodel.Ack{ResponseID: "response-file", TenantID: "default", AgentID: "agent-a"})
	if err == nil || ok || st.Responses[0].Status != "pending" || len(st.ResponseAcks) != 0 {
		t.Fatalf("AckResponse ok=%t err=%v responses=%+v acks=%+v", ok, err, st.Responses, st.ResponseAcks)
	}
}

func TestControlCommandWritesReturnFilePersistenceFailure(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		st := &Store{path: t.TempDir()}
		_, err := st.CreateControlCommand(controlmodel.ControlCommand{CommandID: "control-file", TenantID: "default", AgentID: "agent-a"})
		if err == nil || len(st.ControlCommands) != 0 {
			t.Fatalf("CreateControlCommand err=%v commands=%+v", err, st.ControlCommands)
		}
	})
	t.Run("ack", func(t *testing.T) {
		st := &Store{path: t.TempDir(), ControlCommands: []controlmodel.ControlCommand{{CommandID: "control-file", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusPending}}}
		_, ok, err := st.AckControlCommand(controlmodel.ControlCommandAck{CommandID: "control-file", TenantID: "default", AgentID: "agent-a"})
		if err == nil || ok || st.ControlCommands[0].Status != controlmodel.ControlCommandStatusPending {
			t.Fatalf("AckControlCommand ok=%t err=%v commands=%+v", ok, err, st.ControlCommands)
		}
	})
}

func TestPolicyCommitsReturnFilePersistenceFailure(t *testing.T) {
	t.Run("publish", func(t *testing.T) {
		st := &Store{path: t.TempDir(), Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-file", Version: 1}}}
		_, ok, err := st.PublishPolicyWithAudit("default", "policy-file", 1, true, policymodel.AuditRecord{Action: "policy.publish"})
		if err == nil || ok || st.Policies[0].Published || len(st.PolicyAudits) != 0 {
			t.Fatalf("PublishPolicyWithAudit ok=%t err=%v policies=%+v audits=%+v", ok, err, st.Policies, st.PolicyAudits)
		}
	})
	t.Run("assign", func(t *testing.T) {
		st := &Store{path: t.TempDir(), Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-file", Version: 1, Published: true}}}
		_, _, ok, err := st.AssignPolicyWithAudit(
			policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: "policy-file", PolicyVersion: 1},
			policymodel.AuditRecord{Action: "policy.assign"},
			&controlmodel.ControlCommand{CommandID: "control-file", Type: controlmodel.ControlCommandTypePolicyUpdate},
		)
		if err == nil || ok || len(st.Assignments) != 0 || len(st.PolicyAudits) != 0 || len(st.ControlCommands) != 0 {
			t.Fatalf("AssignPolicyWithAudit ok=%t err=%v assignments=%+v audits=%+v commands=%+v", ok, err, st.Assignments, st.PolicyAudits, st.ControlCommands)
		}
	})
}

func TestResponsesUseTenantScopedIdentity(t *testing.T) {
	st := &Store{}
	for _, cmd := range []responsemodel.Command{
		{ResponseID: "shared", TenantID: "tenant-a", AgentID: "agent-a"},
		{ResponseID: "shared", TenantID: "tenant-b", AgentID: "agent-b"},
	} {
		if _, err := st.CreateResponse(cmd); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.Responses) != 2 {
		t.Fatalf("responses = %+v, want one per tenant", st.Responses)
	}
	if _, ok, err := st.AckResponse(responsemodel.Ack{ResponseID: "shared", TenantID: "tenant-b", AgentID: "agent-b"}); err != nil || !ok {
		t.Fatalf("AckResponse ok=%t err=%v", ok, err)
	}
	if st.Responses[0].Status == "acked" || st.Responses[1].Status != "acked" {
		t.Fatalf("tenant-scoped response states = %+v", st.Responses)
	}
}

func TestCreateResponseDoesNotReopenAckedCommand(t *testing.T) {
	st := &Store{}
	cmd := responsemodel.Command{ResponseID: "response-idempotent", TenantID: "default", AgentID: "agent-a"}
	if _, err := st.CreateResponse(cmd); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := st.AckResponse(responsemodel.Ack{ResponseID: cmd.ResponseID, TenantID: cmd.TenantID, AgentID: cmd.AgentID}); err != nil || !ok {
		t.Fatalf("AckResponse ok=%t err=%v", ok, err)
	}
	got, err := st.CreateResponse(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "acked" || len(st.ResponseAcks) != 1 {
		t.Fatalf("response after duplicate create = %+v acks=%+v", got, st.ResponseAcks)
	}
}

func TestCreateResponseReturnsBackendWinnerAfterConcurrentConflict(t *testing.T) {
	backend := &responseCreateConflictBackend{winner: responsemodel.AuditRecord{Command: responsemodel.Command{
		ResponseID: "response-conflict", TenantID: "default", AgentID: "agent-winner", Status: "acked",
	}, Ack: &responsemodel.Ack{ResponseID: "response-conflict", TenantID: "default", AgentID: "agent-winner"}}}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, err := st.CreateResponse(responsemodel.Command{
		ResponseID: "response-conflict", TenantID: "default", AgentID: "agent-loser", Status: "pending",
	})

	if err != nil || got.AgentID != "agent-winner" || got.Status != "acked" {
		t.Fatalf("CreateResponse got=%+v err=%v, want backend winner", got, err)
	}
}

func TestCreateResponseIgnoresStaleBackendCache(t *testing.T) {
	backend := &responseCreateConflictBackend{listCalls: 1, winner: responsemodel.AuditRecord{Command: responsemodel.Command{
		ResponseID: "response-stale", TenantID: "default", AgentID: "agent-a", Status: "acked",
	}, Ack: &responsemodel.Ack{ResponseID: "response-stale", TenantID: "default", AgentID: "agent-a"}}}
	st := &Store{Responses: []responsemodel.Command{{ResponseID: "response-stale", TenantID: "default", AgentID: "agent-a", Status: "pending"}}}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, err := st.CreateResponse(responsemodel.Command{ResponseID: "response-stale", TenantID: "default", AgentID: "agent-a"})

	if err != nil || got.Status != "acked" {
		t.Fatalf("CreateResponse got=%+v err=%v, want backend terminal state", got, err)
	}
}

type responseCreateConflictBackend struct {
	Backend
	winner    responsemodel.AuditRecord
	listCalls int
}

func (b *responseCreateConflictBackend) ListResponses(context.Context, string, string) ([]responsemodel.AuditRecord, error) {
	b.listCalls++
	if b.listCalls == 1 {
		return nil, nil
	}
	return []responsemodel.AuditRecord{b.winner}, nil
}

func (*responseCreateConflictBackend) WriteResponse(context.Context, responsemodel.Command, *responsemodel.Ack) error {
	return nil
}

func (*responseCreateConflictBackend) CreateResponse(context.Context, responsemodel.Command) (bool, error) {
	return false, nil
}

func TestControlCommandsUseTenantScopedIdentityAndPreserveTerminalState(t *testing.T) {
	st := &Store{}
	for _, cmd := range []controlmodel.ControlCommand{
		{CommandID: "shared", TenantID: "tenant-a", AgentID: "agent-a"},
		{CommandID: "shared", TenantID: "tenant-b", AgentID: "agent-b"},
	} {
		if _, err := st.CreateControlCommand(cmd); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.ControlCommands) != 2 {
		t.Fatalf("control commands = %+v, want one per tenant", st.ControlCommands)
	}
	if _, ok, err := st.AckControlCommand(controlmodel.ControlCommandAck{CommandID: "shared", TenantID: "tenant-b", AgentID: "agent-b"}); err != nil || !ok {
		t.Fatalf("AckControlCommand ok=%t err=%v", ok, err)
	}
	got, err := st.CreateControlCommand(controlmodel.ControlCommand{CommandID: "shared", TenantID: "tenant-b", AgentID: "agent-b"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != controlmodel.ControlCommandStatusApplied || st.ControlCommands[0].Status != controlmodel.ControlCommandStatusPending {
		t.Fatalf("control commands after duplicate create = %+v", st.ControlCommands)
	}
}

func TestCreateControlCommandReturnsBackendWinnerAfterConcurrentConflict(t *testing.T) {
	backend := &controlCreateConflictBackend{winner: controlmodel.ControlCommand{
		CommandID: "control-conflict", TenantID: "default", AgentID: "agent-winner", Status: controlmodel.ControlCommandStatusApplied,
	}}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, err := st.CreateControlCommand(controlmodel.ControlCommand{
		CommandID: "control-conflict", TenantID: "default", AgentID: "agent-loser", Status: controlmodel.ControlCommandStatusPending,
	})

	if err != nil || got.AgentID != "agent-winner" || got.Status != controlmodel.ControlCommandStatusApplied {
		t.Fatalf("CreateControlCommand got=%+v err=%v, want backend winner", got, err)
	}
}

func TestCreateControlCommandIgnoresStaleBackendCache(t *testing.T) {
	backend := &controlCreateConflictBackend{listCalls: 1, winner: controlmodel.ControlCommand{
		CommandID: "control-stale", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusApplied,
	}}
	st := &Store{ControlCommands: []controlmodel.ControlCommand{{
		CommandID: "control-stale", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusPending,
	}}}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, err := st.CreateControlCommand(controlmodel.ControlCommand{CommandID: "control-stale", TenantID: "default", AgentID: "agent-a"})

	if err != nil || got.Status != controlmodel.ControlCommandStatusApplied {
		t.Fatalf("CreateControlCommand got=%+v err=%v, want backend terminal state", got, err)
	}
}

type controlCreateConflictBackend struct {
	Backend
	winner    controlmodel.ControlCommand
	listCalls int
}

func (b *controlCreateConflictBackend) ListControlCommands(context.Context, string, string, string) ([]controlmodel.ControlCommand, error) {
	b.listCalls++
	if b.listCalls == 1 {
		return nil, nil
	}
	return []controlmodel.ControlCommand{b.winner}, nil
}

func (*controlCreateConflictBackend) CreateControlCommand(context.Context, controlmodel.ControlCommand) (bool, error) {
	return false, nil
}

func TestCreateResponseBackendWriteDoesNotBlockStoreReads(t *testing.T) {
	backend := &blockingResponseBackend{started: make(chan struct{}), release: make(chan struct{})}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})
	writeDone := make(chan error, 1)
	go func() {
		_, err := st.CreateResponse(responsemodel.Command{ResponseID: "response-blocked", TenantID: "default", AgentID: "agent-a"})
		writeDone <- err
	}()
	<-backend.started
	readDone := make(chan struct{})
	go func() {
		st.mu.RLock()
		st.mu.RUnlock()
		close(readDone)
	}()
	select {
	case <-readDone:
	case <-time.After(100 * time.Millisecond):
		close(backend.release)
		<-writeDone
		t.Fatal("store read blocked by response backend write")
	}
	close(backend.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("CreateResponse error = %v", err)
	}
}

func TestSaveSerializesWithDurableControlWrites(t *testing.T) {
	backend := &blockingSaveBackend{
		saveStarted: make(chan struct{}), releaseSave: make(chan struct{}), ackStarted: make(chan struct{}),
	}
	st := &Store{ControlCommands: []controlmodel.ControlCommand{{
		CommandID: "control-save-race", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusPending,
	}}}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})
	saveDone := make(chan error, 1)
	go func() { saveDone <- st.Save() }()
	<-backend.saveStarted
	ackDone := make(chan error, 1)
	go func() {
		_, _, err := st.AckControlCommand(controlmodel.ControlCommandAck{CommandID: "control-save-race", TenantID: "default", AgentID: "agent-a"})
		ackDone <- err
	}()
	select {
	case <-backend.ackStarted:
		close(backend.releaseSave)
		<-saveDone
		<-ackDone
		t.Fatal("control ACK reached backend before concurrent Save completed")
	case <-time.After(100 * time.Millisecond):
	}
	close(backend.releaseSave)
	if err := <-saveDone; err != nil {
		t.Fatalf("Save error = %v", err)
	}
	if err := <-ackDone; err != nil {
		t.Fatalf("AckControlCommand error = %v", err)
	}
}

type blockingSaveBackend struct {
	Backend
	saveStarted chan struct{}
	releaseSave chan struct{}
	ackStarted  chan struct{}
}

func (b *blockingSaveBackend) SaveState(context.Context, State) error {
	close(b.saveStarted)
	<-b.releaseSave
	return nil
}

func (b *blockingSaveBackend) WriteControlCommand(context.Context, controlmodel.ControlCommand) error {
	close(b.ackStarted)
	return nil
}

type blockingResponseBackend struct {
	Backend
	started chan struct{}
	release chan struct{}
}

func (b *blockingResponseBackend) ListResponses(context.Context, string, string) ([]responsemodel.AuditRecord, error) {
	return nil, nil
}

func (b *blockingResponseBackend) WriteResponse(context.Context, responsemodel.Command, *responsemodel.Ack) error {
	return nil
}

func (b *blockingResponseBackend) CreateResponse(context.Context, responsemodel.Command) (bool, error) {
	close(b.started)
	<-b.release
	return true, nil
}

func TestAckResponseReturnsBackendFailure(t *testing.T) {
	st := &Store{Responses: []responsemodel.Command{{ResponseID: "response-fail", TenantID: "default", AgentID: "agent-a", Status: "pending"}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "response"}, Info{Backend: "test"})

	_, ok, err := st.AckResponse(responsemodel.Ack{ResponseID: "response-fail", AgentID: "agent-a"})
	if err == nil || ok || !strings.Contains(err.Error(), "write response ack") {
		t.Fatalf("AckResponse ok=%t error=%v, want backend write failure", ok, err)
	}
	if st.Responses[0].Status != "pending" || len(st.ResponseAcks) != 0 {
		t.Fatalf("response state after failed ack = responses=%+v acks=%+v", st.Responses, st.ResponseAcks)
	}
}

func TestCreateControlCommandReturnsBackendFailure(t *testing.T) {
	st := &Store{}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "control"}, Info{Backend: "test"})

	_, err := st.CreateControlCommand(controlmodel.ControlCommand{CommandID: "control-fail", TenantID: "default", AgentID: "agent-a"})
	if err == nil || !strings.Contains(err.Error(), "write control command") {
		t.Fatalf("CreateControlCommand error = %v, want backend write failure", err)
	}
	if len(st.ControlCommands) != 0 {
		t.Fatalf("control commands after failed write = %+v, want unchanged", st.ControlCommands)
	}
}

func TestAckControlCommandReturnsBackendFailure(t *testing.T) {
	st := &Store{ControlCommands: []controlmodel.ControlCommand{{CommandID: "control-fail", TenantID: "default", AgentID: "agent-a", Status: controlmodel.ControlCommandStatusPending}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "control"}, Info{Backend: "test"})

	_, ok, err := st.AckControlCommand(controlmodel.ControlCommandAck{CommandID: "control-fail", TenantID: "default", AgentID: "agent-a"})
	if err == nil || ok || !strings.Contains(err.Error(), "write control command ack") {
		t.Fatalf("AckControlCommand ok=%t error=%v, want backend write failure", ok, err)
	}
	if st.ControlCommands[0].Status != controlmodel.ControlCommandStatusPending {
		t.Fatalf("control command after failed ack = %+v, want pending", st.ControlCommands[0])
	}
}

func TestPublishPolicyReturnsBackendFailure(t *testing.T) {
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "policy"}, Info{Backend: "test"})

	_, ok, err := st.PublishPolicy("default", "policy-fail", 1, true)
	if err == nil || ok || !strings.Contains(err.Error(), "write policy publication") {
		t.Fatalf("PublishPolicy ok=%t error=%v, want backend write failure", ok, err)
	}
	if st.Policies[0].Published {
		t.Fatalf("policy after failed publish = %+v, want unpublished", st.Policies[0])
	}
}

func TestAssignPolicyReturnsBackendFailure(t *testing.T) {
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1, Published: true}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "assignment"}, Info{Backend: "test"})

	_, ok, err := st.AssignPolicy(policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: "policy-fail", PolicyVersion: 1})
	if err == nil || ok || !strings.Contains(err.Error(), "write policy assignment") {
		t.Fatalf("AssignPolicy ok=%t error=%v, want backend write failure", ok, err)
	}
	if len(st.Assignments) != 0 {
		t.Fatalf("assignments after failed write = %+v, want unchanged", st.Assignments)
	}
}

func TestPublishPolicyWithAuditRollsBackOnCommitFailure(t *testing.T) {
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "publication_commit"}, Info{Backend: "test"})

	_, ok, err := st.PublishPolicyWithAudit("default", "policy-fail", 1, true, policymodel.AuditRecord{Action: "policy.publish"})
	if err == nil || ok || !strings.Contains(err.Error(), "commit policy publication") {
		t.Fatalf("PublishPolicyWithAudit ok=%t error=%v, want commit failure", ok, err)
	}
	if st.Policies[0].Published || len(st.PolicyAudits) != 0 {
		t.Fatalf("publication after failed commit = policies=%+v audits=%+v", st.Policies, st.PolicyAudits)
	}
}

func TestAssignPolicyWithAuditRollsBackOnCommitFailure(t *testing.T) {
	st := &Store{Policies: []policymodel.Policy{{TenantID: "default", PolicyID: "policy-fail", Version: 1, Published: true}}}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "assignment_commit"}, Info{Backend: "test"})
	command := &controlmodel.ControlCommand{CommandID: "control-fail", Type: controlmodel.ControlCommandTypePolicyUpdate}

	_, _, ok, err := st.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: "policy-fail", PolicyVersion: 1},
		policymodel.AuditRecord{Action: "policy.assign"},
		command,
	)
	if err == nil || ok || !strings.Contains(err.Error(), "commit policy assignment") {
		t.Fatalf("AssignPolicyWithAudit ok=%t error=%v, want commit failure", ok, err)
	}
	if len(st.Assignments) != 0 || len(st.PolicyAudits) != 0 || len(st.ControlCommands) != 0 {
		t.Fatalf("assignment after failed commit = assignments=%+v audits=%+v commands=%+v", st.Assignments, st.PolicyAudits, st.ControlCommands)
	}
}

func TestPublishPolicyWithAuditLoadsPolicyFromBackend(t *testing.T) {
	backend := &restartingControlPlaneBackend{policy: policymodel.Policy{
		TenantID: "default", PolicyID: "policy-restart", Version: 3,
	}}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, ok, err := st.PublishPolicyWithAudit("default", "policy-restart", 3, true, policymodel.AuditRecord{Action: "policy.publish"})

	if err != nil || !ok || !got.Published || backend.published.PolicyID != "policy-restart" {
		t.Fatalf("PublishPolicyWithAudit got=%+v ok=%t err=%v committed=%+v", got, ok, err, backend.published)
	}
}

func TestAssignPolicyWithAuditLoadsPolicyAndAssignmentFromBackend(t *testing.T) {
	createdAt := time.Unix(100, 0).UTC()
	backend := &restartingControlPlaneBackend{
		policy: policymodel.Policy{TenantID: "default", PolicyID: "policy-restart", Version: 3, Published: true},
		assignments: []policymodel.Assignment{{
			AssignmentID: "existing-assignment", TenantID: "default", AgentID: "agent-a",
			PolicyID: "policy-restart", PolicyVersion: 3, CreatedAt: createdAt,
		}},
	}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got, _, ok, err := st.AssignPolicyWithAudit(
		policymodel.Assignment{TenantID: "default", AgentID: "agent-a", PolicyID: "policy-restart", PolicyVersion: 3},
		policymodel.AuditRecord{Action: "policy.assign"}, nil,
	)

	if err != nil || !ok || !got.CreatedAt.Equal(createdAt) || backend.assigned.PolicyID != "policy-restart" {
		t.Fatalf("AssignPolicyWithAudit got=%+v ok=%t err=%v committed=%+v", got, ok, err, backend.assigned)
	}
}

func TestPendingResponsesLoadsFromBackend(t *testing.T) {
	backend := &restartingControlPlaneBackend{responses: []responsemodel.AuditRecord{
		{Command: responsemodel.Command{ResponseID: "pending-restart", TenantID: "default", AgentID: "agent-a", Status: "pending"}},
		{Command: responsemodel.Command{ResponseID: "acked-restart", TenantID: "default", AgentID: "agent-a", Status: "pending"}, Ack: &responsemodel.Ack{ResponseID: "acked-restart", TenantID: "default", AgentID: "agent-a"}},
	}}
	st := &Store{}
	st.AttachBackend(context.Background(), backend, Info{Backend: "test"})

	got := st.PendingResponses("default", "agent-a")

	if len(got) != 1 || got[0].ResponseID != "pending-restart" {
		t.Fatalf("PendingResponses = %+v, want backend pending response", got)
	}
}

func TestRevokeAgentCertificateIsIdempotentAndRejectsIdentityConflict(t *testing.T) {
	st := &Store{}
	st.RecordAgentCertificate(AgentCertificate{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", SerialNumber: "42",
	})
	revokedAt := time.Unix(100, 0).UTC()
	first, ok, err := st.RevokeAgentCertificate("tenant-a", "agent-a", "enroll-a", "42", revokedAt)
	if err != nil || !ok || first.RevocationReceipt == "" || !first.RevokedAt.Equal(revokedAt) {
		t.Fatalf("first revoke=%+v ok=%t err=%v", first, ok, err)
	}
	legacyRecord, ok, err := st.GetUnenrollmentWithError("tenant-a", "enroll-a")
	if err != nil || !ok || legacyRecord.Status != UnenrollmentUnknownLegacy || legacyRecord.RevocationReceipt != first.RevocationReceipt {
		t.Fatalf("legacy record=%+v ok=%t err=%v", legacyRecord, ok, err)
	}
	second, ok, err := st.RevokeAgentCertificate("tenant-a", "agent-a", "enroll-a", "42", revokedAt.Add(time.Hour))
	if err != nil || !ok || second.RevocationReceipt != first.RevocationReceipt || !second.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("replayed revoke=%+v ok=%t err=%v", second, ok, err)
	}
	if _, _, err := st.RevokeAgentCertificate("tenant-a", "agent-other", "enroll-a", "42", revokedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("identity conflict error=%v, want ErrConflict", err)
	}
	st.RecordAgentCertificate(AgentCertificate{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-legacy", SerialNumber: "43", RevokedAt: revokedAt,
	})
	legacy, ok, err := st.RevokeAgentCertificate("tenant-a", "agent-a", "enroll-legacy", "43", revokedAt.Add(time.Hour))
	if err != nil || !ok || legacy.RevocationReceipt == "" || !legacy.RevokedAt.Equal(revokedAt) {
		t.Fatalf("legacy revoked certificate=%+v ok=%t err=%v", legacy, ok, err)
	}
}

func TestAuthorizeAgentUnenrollmentIsIdempotent(t *testing.T) {
	st := &Store{}
	st.RecordAgentCertificate(AgentCertificate{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", SerialNumber: "42",
	})
	tokenHash := strings.Repeat("a", 64)
	revokedAt := time.Unix(100, 0).UTC()

	first, ok, err := st.AuthorizeAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", tokenHash, revokedAt)
	if err != nil || !ok || first.Status != UnenrollmentRevokedEndpointPending || first.RevocationReceipt == "" || !first.RevokedAt.Equal(revokedAt) {
		t.Fatalf("first=%+v ok=%t err=%v", first, ok, err)
	}
	replayed, ok, err := st.AuthorizeAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", tokenHash, revokedAt.Add(time.Hour))
	if err != nil || !ok || replayed.RevocationReceipt != first.RevocationReceipt || !replayed.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("replayed=%+v ok=%t err=%v", replayed, ok, err)
	}
	if _, _, err := st.AuthorizeAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", strings.Repeat("b", 64), revokedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("token hash conflict error=%v, want ErrConflict", err)
	}
	certificate, ok, err := st.GetAgentCertificateWithError("tenant-a", "42")
	if err != nil || !ok || certificate.RevocationReceipt != first.RevocationReceipt || !certificate.RevokedAt.Equal(revokedAt) {
		t.Fatalf("certificate=%+v ok=%t err=%v", certificate, ok, err)
	}
}

func TestCompleteAgentUnenrollmentValidatesBindingsAndIsIdempotent(t *testing.T) {
	st := &Store{}
	st.RecordAgentCertificate(AgentCertificate{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", SerialNumber: "42",
	})
	tokenHash := strings.Repeat("a", 64)
	record, ok, err := st.AuthorizeAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", tokenHash, time.Unix(100, 0).UTC())
	if err != nil || !ok {
		t.Fatalf("authorize=%+v ok=%t err=%v", record, ok, err)
	}
	if _, _, err := st.CompleteAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", record.RevocationReceipt, strings.Repeat("b", 64), time.Unix(200, 0).UTC()); !errors.Is(err, ErrConflict) {
		t.Fatalf("completion conflict error=%v, want ErrConflict", err)
	}
	pending, ok, err := st.GetUnenrollmentWithError("tenant-a", "enroll-a")
	if err != nil || !ok || pending.Status != UnenrollmentRevokedEndpointPending {
		t.Fatalf("pending=%+v ok=%t err=%v", pending, ok, err)
	}

	completedAt := time.Unix(200, 0).UTC()
	completed, ok, err := st.CompleteAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", record.RevocationReceipt, tokenHash, completedAt)
	if err != nil || !ok || completed.Status != UnenrollmentEndpointCompleted || !completed.EndpointCompletedAt.Equal(completedAt) {
		t.Fatalf("completed=%+v ok=%t err=%v", completed, ok, err)
	}
	replayed, ok, err := st.CompleteAgentUnenrollment("tenant-a", "agent-a", "enroll-a", "42", record.RevocationReceipt, tokenHash, completedAt.Add(time.Hour))
	if err != nil || !ok || !replayed.EndpointCompletedAt.Equal(completedAt) {
		t.Fatalf("replayed=%+v ok=%t err=%v", replayed, ok, err)
	}
}

func TestPendingResponsesWithErrorReturnsBackendFailure(t *testing.T) {
	st := &Store{}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "response_read"}, Info{Backend: "test"})

	if _, err := st.PendingResponsesWithError("default", "agent-a"); err == nil {
		t.Fatal("PendingResponsesWithError error = nil, want backend failure")
	}
}

func TestSecurityControlReadsWithErrorReturnBackendFailure(t *testing.T) {
	st := &Store{}
	st.AttachBackend(context.Background(), failingControlPlaneBackend{operation: "security_read"}, Info{Backend: "test"})

	checks := []struct {
		name string
		read func() error
	}{
		{"enrollments", func() error { _, err := st.ListEnrollmentsWithError("default", ""); return err }},
		{"enrollment token", func() error { _, _, err := st.GetEnrollmentByTokenHashWithError("hash"); return err }},
		{"bootstrap token", func() error { _, _, err := st.GetEnrollmentByBootstrapTokenHashWithError("hash"); return err }},
		{"artifacts", func() error { _, err := st.ListArtifactsWithError("default", "", ""); return err }},
		{"artifact", func() error { _, _, err := st.GetArtifactWithError("default", "artifact-a"); return err }},
		{"channels", func() error { _, err := st.ListChannelsWithError("default"); return err }},
		{"channel", func() error { _, _, err := st.GetChannelWithError("default", "stable"); return err }},
		{"evidence pullback", func() error {
			_, _, err := st.GetEvidencePullbackWithError("request-a", "default", "agent-a")
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.read(); err == nil {
				t.Fatal("error=nil, want backend failure")
			}
		})
	}
}

type restartingControlPlaneBackend struct {
	Backend
	policy      policymodel.Policy
	assignments []policymodel.Assignment
	responses   []responsemodel.AuditRecord
	published   policymodel.Policy
	assigned    policymodel.Assignment
}

func (b *restartingControlPlaneBackend) GetPolicy(context.Context, string, string, uint64) (policymodel.Policy, bool, error) {
	return b.policy, b.policy.PolicyID != "", nil
}

func (b *restartingControlPlaneBackend) ListAssignments(context.Context, string, string) ([]policymodel.Assignment, error) {
	return append([]policymodel.Assignment(nil), b.assignments...), nil
}

func (b *restartingControlPlaneBackend) ListResponses(context.Context, string, string) ([]responsemodel.AuditRecord, error) {
	return append([]responsemodel.AuditRecord(nil), b.responses...), nil
}

func (b *restartingControlPlaneBackend) CommitPolicyPublication(_ context.Context, policy policymodel.Policy, _ policymodel.AuditRecord) error {
	b.published = policy
	return nil
}

func (b *restartingControlPlaneBackend) CommitPolicyAssignment(_ context.Context, assignment policymodel.Assignment, _ policymodel.AuditRecord, command *controlmodel.ControlCommand) (*controlmodel.ControlCommand, error) {
	b.assigned = assignment
	return command, nil
}

type failingControlPlaneBackend struct {
	Backend
	operation string
}

func (b failingControlPlaneBackend) ListEnrollments(context.Context, string, string) ([]Enrollment, error) {
	return nil, b.readFailure()
}

func (b failingControlPlaneBackend) GetEnrollmentByTokenHash(context.Context, string) (Enrollment, bool, error) {
	return Enrollment{}, false, b.readFailure()
}

func (b failingControlPlaneBackend) GetEnrollmentByBootstrapTokenHash(context.Context, string) (Enrollment, bool, error) {
	return Enrollment{}, false, b.readFailure()
}

func (b failingControlPlaneBackend) ListArtifacts(context.Context, string, string, string) ([]Artifact, error) {
	return nil, b.readFailure()
}

func (b failingControlPlaneBackend) GetArtifact(context.Context, string, string) (Artifact, bool, error) {
	return Artifact{}, false, b.readFailure()
}

func (b failingControlPlaneBackend) ListChannels(context.Context, string) ([]ArtifactChannel, error) {
	return nil, b.readFailure()
}

func (b failingControlPlaneBackend) GetChannel(context.Context, string, string) (ArtifactChannel, bool, error) {
	return ArtifactChannel{}, false, b.readFailure()
}

func (b failingControlPlaneBackend) ListEvidencePullbacks(context.Context, string, string) ([]controlmodel.EvidencePullbackRequest, error) {
	return nil, b.readFailure()
}

func (b failingControlPlaneBackend) readFailure() error {
	if b.operation == "security_read" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) WriteResponse(context.Context, responsemodel.Command, *responsemodel.Ack) error {
	if b.operation == "response" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) CreateResponse(context.Context, responsemodel.Command) (bool, error) {
	if b.operation == "response" {
		return false, errors.New("backend down")
	}
	return true, nil
}

func (b failingControlPlaneBackend) WritePolicy(context.Context, policymodel.Policy) error {
	if b.operation == "policy" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) WriteAssignment(context.Context, policymodel.Assignment) error {
	if b.operation == "assignment" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) WriteControlCommand(context.Context, controlmodel.ControlCommand) error {
	if b.operation == "control" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) CreateControlCommand(context.Context, controlmodel.ControlCommand) (bool, error) {
	if b.operation == "control" {
		return false, errors.New("backend down")
	}
	return true, nil
}

func (b failingControlPlaneBackend) ListResponses(context.Context, string, string) ([]responsemodel.AuditRecord, error) {
	if b.operation == "response_read" {
		return nil, errors.New("backend down")
	}
	return nil, nil
}

func (failingControlPlaneBackend) ListControlCommands(context.Context, string, string, string) ([]controlmodel.ControlCommand, error) {
	return nil, nil
}

func (failingControlPlaneBackend) GetPolicy(context.Context, string, string, uint64) (policymodel.Policy, bool, error) {
	return policymodel.Policy{}, false, nil
}

func (failingControlPlaneBackend) ListAssignments(context.Context, string, string) ([]policymodel.Assignment, error) {
	return nil, nil
}

func (b failingControlPlaneBackend) CommitPolicyPublication(context.Context, policymodel.Policy, policymodel.AuditRecord) error {
	if b.operation == "publication_commit" {
		return errors.New("backend down")
	}
	return nil
}

func (b failingControlPlaneBackend) CommitPolicyAssignment(_ context.Context, _ policymodel.Assignment, _ policymodel.AuditRecord, command *controlmodel.ControlCommand) (*controlmodel.ControlCommand, error) {
	if b.operation == "assignment_commit" {
		return nil, errors.New("backend down")
	}
	return command, nil
}

func TestPolicyAssignmentAndEffectivePolicy(t *testing.T) {
	st := &Store{}
	st.EnsureDefaultPolicy("default")
	if rules := st.ListRules(""); len(rules) == 0 {
		t.Fatal("default rules were not seeded")
	}
	if policy, ok := st.EffectivePolicy("default", "agent-a", "container", "abc123"); !ok || policy.PolicyID != policymodel.DefaultPolicyID || policy.Version != policymodel.DefaultPolicyVersion {
		t.Fatalf("default effective policy = %+v ok=%t", policy, ok)
	}

	custom := policymodel.DefaultPolicy("default")
	custom.PolicyID = "cloud-no-cross"
	custom.Version = 2
	custom.CloudRules = []string{"web_shell_chain"}
	st.UpsertPolicy(custom)
	assignment, ok, err := st.AssignPolicy(policymodel.Assignment{
		TenantID:      "default",
		Scope:         policymodel.ScopeSelector{Type: "container", Selector: "abc123"},
		PolicyID:      "cloud-no-cross",
		PolicyVersion: 2,
	})
	if err != nil || !ok || assignment.PolicyVersion != 2 {
		t.Fatalf("assignment = %+v ok=%t err=%v", assignment, ok, err)
	}
	policy, ok := st.EffectivePolicy("default", "agent-a", "container", "abc123")
	if !ok || policy.PolicyID != "cloud-no-cross" || len(policy.CloudRules) != 1 || policy.CloudRules[0] != "web_shell_chain" {
		t.Fatalf("effective scoped policy = %+v ok=%t", policy, ok)
	}
	other, ok := st.EffectivePolicy("default", "agent-a", "container", "other")
	if !ok || other.PolicyID != policymodel.DefaultPolicyID {
		t.Fatalf("effective fallback policy = %+v ok=%t", other, ok)
	}
}

func TestPolicyDraftMustBePublishedBeforeAssignment(t *testing.T) {
	st := &Store{}
	st.EnsureDefaultPolicy("default")
	draft := policymodel.DefaultPolicy("default")
	draft.PolicyID = "draft-policy"
	draft.Version = 2
	draft.Published = false
	st.UpsertPolicy(draft)
	if _, ok, err := st.AssignPolicy(policymodel.Assignment{
		TenantID:      "default",
		AgentID:       "agent-a",
		PolicyID:      "draft-policy",
		PolicyVersion: 2,
	}); err != nil || ok {
		t.Fatalf("AssignPolicy ok=%t err=%v for draft policy", ok, err)
	}
	if effective, ok := st.EffectivePolicy("default", "agent-a", "", ""); !ok || effective.PolicyID != policymodel.DefaultPolicyID {
		t.Fatalf("effective policy = %+v ok=%t", effective, ok)
	}
	published, ok, err := st.PublishPolicy("default", "draft-policy", 2, true)
	if err != nil || !ok || !published.Published {
		t.Fatalf("PublishPolicy = %+v ok=%t err=%v", published, ok, err)
	}
	if _, ok, err := st.AssignPolicy(policymodel.Assignment{
		TenantID:      "default",
		AgentID:       "agent-a",
		PolicyID:      "draft-policy",
		PolicyVersion: 2,
	}); err != nil || !ok {
		t.Fatalf("AssignPolicy ok=%t err=%v after publish", ok, err)
	}
	if effective, ok := st.EffectivePolicy("default", "agent-a", "", ""); !ok || effective.PolicyID != "draft-policy" || !effective.Published {
		t.Fatalf("effective policy = %+v ok=%t", effective, ok)
	}
}

func TestPolicyAuditPersistsAcrossStateExport(t *testing.T) {
	st := &Store{}
	st.RecordPolicyAudit(policymodel.AuditRecord{
		TenantID:      "default",
		Action:        "policy.publish",
		PolicyID:      "policy-a",
		PolicyVersion: 2,
		Actor:         "analyst",
	})
	state, err := st.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored := &Store{}
	if err := restored.ImportState(state); err != nil {
		t.Fatal(err)
	}
	got := restored.ListPolicyAudits("default", "policy-a")
	if len(got) != 1 || got[0].Action != "policy.publish" || got[0].Actor != "analyst" || got[0].AuditID == "" {
		t.Fatalf("policy audit = %+v", got)
	}
}

func testEvent(id, scenario string) *eventv1.CanonicalEvent {
	return &eventv1.CanonicalEvent{Id: id, Labels: scenarioMap(scenario)}
}

func testSignal(id, scenario string, where signalv1.SignalWhere, name, lineage, entity string) *signalv1.Signal {
	return &signalv1.Signal{
		Id:        id,
		Labels:    scenarioMap(scenario),
		Where:     where,
		Name:      name,
		LineageId: lineage,
		Entities:  []*signalv1.EntityRef{{Kind: "file", Key: entity, Role: "object"}},
		EventRefs: []string{"ev-1"},
	}
}

func scenarioLabels(scenario string) LabelSelector {
	return LabelSelector{"scenario": scenario}
}

func scenarioMap(scenario string) map[string]string {
	return map[string]string{"scenario": scenario}
}
