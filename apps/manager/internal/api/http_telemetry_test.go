package managerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestSearchBackedTelemetryQueries(t *testing.T) {
	st := &store.Store{}
	searcher := fakeSearcher{docs: map[string][]json.RawMessage{
		"sysarmor-events-read": {
			json.RawMessage(`{"id":"ev-a","tenant_id":"default","behavior":"process.exec","labels":{"scenario":"managed"}}`),
			json.RawMessage(`{"id":"ev-b","tenant_id":"default","behavior":"file.write","labels":{"scenario":"other"}}`),
		},
		"sysarmor-signals-read": {
			json.RawMessage(`{"id":"sig-a","tenant_id":"default","name":"payload_dropped","where":"SIGNAL_WHERE_ENDPOINT","terminal":false,"labels":{"scenario":"managed"}}`),
			json.RawMessage(`{"id":"sig-b","tenant_id":"default","name":"web_shell_chain","where":"SIGNAL_WHERE_CLOUD","terminal":true,"labels":{"scenario":"managed"}}`),
		},
		"sysarmor-incidents-read": {
			json.RawMessage(`{"id":"inc-a","tenant_id":"default","summary":"incident","labels":{"scenario":"managed"}}`),
		},
	}}
	handler := adminTestHandler(NewServerWithSearch(st, searcher))

	rec := get(t, handler, "/api/v1/events?label=scenario=managed&behavior=process.exec")
	if !strings.Contains(rec.Body.String(), `"id":"ev-a"`) || strings.Contains(rec.Body.String(), `"id":"ev-b"`) {
		t.Fatalf("search-backed events mismatch: %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/signals?label=scenario=managed&layer=cloud&terminal=true")
	if !strings.Contains(rec.Body.String(), `"id":"sig-b"`) || strings.Contains(rec.Body.String(), `"id":"sig-a"`) {
		t.Fatalf("search-backed signals mismatch: %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/incidents?tenant_id=default&label=scenario=managed")
	if !strings.Contains(rec.Body.String(), `"id":"inc-a"`) {
		t.Fatalf("search-backed incidents mismatch: %s", rec.Body.String())
	}
}

func TestEventsAndSignalsScopeSearchToPrincipalTenant(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.EventsReadAlias: {
			json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a"}`),
			json.RawMessage(`{"id":"event-b","tenant_id":"tenant-b"}`),
		},
		platformopensearch.SignalsReadAlias: {
			json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a"}`),
			json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-b"}`),
		},
	}}
	handler := (&authenticatedTestServer{
		Server: NewServerWithSearch(&store.Store{}, searcher),
		principal: managerauth.Principal{
			Subject: "viewer-a", TenantID: "tenant-a", Roles: []string{"viewer"},
		},
	}).Handler()
	for _, path := range []string{"/api/v1/events", "/api/v1/signals"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), "tenant-b") {
			t.Fatalf("GET %s leaked tenant-b: %s", path, rec.Body.String())
		}
	}
	for _, request := range searcher.requests {
		if request.Exact["tenant_id"] != "tenant-a" {
			t.Fatalf("telemetry tenant filter = %#v", request.Exact)
		}
	}
}

func TestLocalTelemetryAndMetricsAreScopedToPrincipalTenant(t *testing.T) {
	st := &store.Store{}
	st.AddEvent(&eventv1.CanonicalEvent{Id: "event-a", TenantId: "tenant-a"})
	st.AddEvent(&eventv1.CanonicalEvent{Id: "event-b", TenantId: "tenant-b"})
	st.AddSignalForTenant("tenant-a", &signalv1.Signal{Id: "signal-a"})
	st.AddSignalForTenant("tenant-b", &signalv1.Signal{Id: "signal-b"})
	seedTenantTelemetry(t, st, "tenant-a", "metrics-a", store.Metrics{DataBatchesAppended: 1, EventsIngested: 1, SignalsEmitted: 1}, nil)
	seedTenantTelemetry(t, st, "tenant-b", "metrics-b", store.Metrics{DataBatchesAppended: 1, EventsIngested: 20, SignalsEmitted: 30}, nil)
	handler := tenantTestHandler(newTestServer(st), "tenant-a")

	for _, path := range []string{"/api/v1/events", "/api/v1/signals", "/api/v1/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), "event-b") || strings.Contains(rec.Body.String(), "signal-b") || strings.Contains(rec.Body.String(), `"events_ingested":21`) {
			t.Fatalf("GET %s leaked tenant-b: %s", path, rec.Body.String())
		}
	}
}

func TestRarityBaselineIsScopedToPrincipalTenant(t *testing.T) {
	st := &store.Store{}
	signalA := &signalv1.Signal{Name: "download_by_lolbin", Labels: map[string]string{"workload": "container:checkout-api"}}
	signalB := &signalv1.Signal{Name: "other_tenant_signal", Labels: map[string]string{"workload": "container:billing"}}
	seedTenantTelemetry(t, st, "tenant-a", "rarity-a", store.Metrics{}, []*signalv1.Signal{signalA})
	seedTenantTelemetry(t, st, "tenant-b", "rarity-b", store.Metrics{}, []*signalv1.Signal{signalB})
	handler := tenantTestHandler(newTestServer(st), "tenant-a")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rarity-baseline?workload=container:checkout-api&signal=download_by_lolbin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), `"count":1`) || strings.Contains(rec.Body.String(), "other_tenant_signal") {
		t.Fatalf("rarity response = %s", rec.Body.String())
	}
}

func TestUploadTriggersAnalyticsAndQueries(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	batch := httpDataBatch("", "agent-a", "host-a", nil, []*signalv1.Signal{
		endpointSignal("web_runtime_spawns_shell", "lin-a", false, processEntity("p-web")),
		endpointSignal("payload_dropped", "lin-a", false, fileEntity("/dev/shm/x.sh")),
		endpointSignal("reverse_shell_pattern", "lin-a", true, processEntity("p-bash"), socketEntity("10.66.0.99:443")),
	})
	appendBatch(t, srv, batch)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals?label=scenario=apt-fileless-c2&layer=cloud", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signals status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "web_shell_chain") {
		t.Fatalf("cloud signals missing web_shell_chain: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/incidents?label=scenario=apt-fileless-c2", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("incidents status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "rarity+causal-topk") {
		t.Fatalf("incident missing converge method: %s", rec.Body.String())
	}

	rec = get(t, handler, "/api/v1/metrics")
	for _, want := range []string{
		`"data_batches_appended":1`,
		`"endpoint_signals_ingested":3`,
		`"cloud_signals_emitted":2`,
		`"signals_emitted":5`,
		`"incidents_created":1`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestDataBatchAppendRecordsSessionCursor(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	batch := httpDataBatch("00000000000000000042", "agent-a", "host-a", []*eventv1.CanonicalEvent{{
		Id:       "ev-ack",
		Behavior: "process.exec",
	}}, nil)
	ack := appendBatchAndAck(t, srv, batch)
	if !ack.GetAccepted() || ack.GetStatus() != dataplanev1.DataAck_STATUS_ACCEPTED || ack.GetBatchId() != batch.GetHeader().GetBatchId() || ack.GetCommittedCursor() != batch.GetHeader().GetBatchId() || ack.GetAcceptedEvents() != 1 || ack.GetServerTime() == "" {
		t.Fatalf("ack = %#v", ack)
	}
	rec := get(t, handler, "/api/v1/agent-sessions?tenant_id=default&agent_id=agent-a")
	for _, want := range []string{`"tenant_id":"default"`, `"agent_id":"agent-a"`, `"last_ack_cursor":"00000000000000000042"`, `"data_transport":"grpc"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("agent session missing %s: %s", want, rec.Body.String())
		}
	}
	rec = get(t, handler, "/api/v1/data-resume?tenant_id=default&agent_id=agent-a")
	if !strings.Contains(rec.Body.String(), `"resume_cursor":"00000000000000000042"`) {
		t.Fatalf("resume cursor mismatch: %s", rec.Body.String())
	}
}

func TestQueryPagination(t *testing.T) {
	st := &store.Store{}
	st.AddEvent(&eventv1.CanonicalEvent{Id: "ev-1", TenantId: "default", Labels: labelsForScenario("page"), Behavior: "process.exec"})
	st.AddEvent(&eventv1.CanonicalEvent{Id: "ev-2", TenantId: "default", Labels: labelsForScenario("page"), Behavior: "file.open"})
	st.AddEvent(&eventv1.CanonicalEvent{Id: "ev-3", TenantId: "default", Labels: labelsForScenario("page"), Behavior: "network.connect"})
	st.AddSignalForTenant("default", endpointSignalForScenario("page", "sig-1", "lin-1", false, processEntity("p1")))
	st.AddSignalForTenant("default", endpointSignalForScenario("page", "sig-2", "lin-2", false, processEntity("p2")))
	st.AddIncident(&incidentv1.Incident{Id: "inc-1", TenantId: "default", Labels: labelsForScenario("page"), Summary: "one"})
	st.AddIncident(&incidentv1.Incident{Id: "inc-2", TenantId: "default", Labels: labelsForScenario("page"), Summary: "two"})
	handler := newAdminTestServer(st).Handler()

	rec := get(t, handler, "/api/v1/events?label=scenario=page&limit=1&offset=1")
	if strings.Contains(rec.Body.String(), `"id":"ev-1"`) || !strings.Contains(rec.Body.String(), `"id":"ev-2"`) || strings.Contains(rec.Body.String(), `"id":"ev-3"`) {
		t.Fatalf("events page mismatch: %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/signals?label=scenario=page&limit=1&offset=1")
	if strings.Contains(rec.Body.String(), `"name":"sig-1"`) || !strings.Contains(rec.Body.String(), `"name":"sig-2"`) {
		t.Fatalf("signals page mismatch: %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/incidents?label=scenario=page&limit=1&offset=1")
	if strings.Contains(rec.Body.String(), `"id":"inc-1"`) || !strings.Contains(rec.Body.String(), `"id":"inc-2"`) {
		t.Fatalf("incidents page mismatch: %s", rec.Body.String())
	}
}

func TestDataBatchAppendRetryIsIdempotentForAcceptedCounts(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	batch := httpDataBatch("00000000000000000007", "agent-a", "host-a", []*eventv1.CanonicalEvent{{
		Id:       "ev-retry",
		Labels:   labelsForScenario("apt-fileless-c2"),
		Behavior: "process.exec",
	}}, []*signalv1.Signal{
		endpointSignal("web_runtime_spawns_shell", "lin-retry", false, processEntity("p-web")),
		endpointSignal("payload_dropped", "lin-retry", false, fileEntity("/dev/shm/x.sh")),
		endpointSignal("reverse_shell_pattern", "lin-retry", true, processEntity("p-bash"), socketEntity("10.66.0.99:443")),
	})
	first := appendBatchAndAck(t, srv, batch)
	if !first.GetAccepted() {
		t.Fatalf("first ack = %#v", first)
	}
	second := appendBatchAndAck(t, srv, batch)
	if !second.GetAccepted() || second.GetStatus() != dataplanev1.DataAck_STATUS_DUPLICATE || second.GetReasonCode() != "duplicate" || second.GetContractVersion() != "dataplane.v1" {
		t.Fatalf("retry ack = %#v, want duplicate idempotent retry", second)
	}

	rec := get(t, handler, "/api/v1/events?label=scenario=apt-fileless-c2")
	if got := strings.Count(rec.Body.String(), `"id":"ev-retry"`); got != 1 {
		t.Fatalf("event count = %d, want 1: %s", got, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/signals?label=scenario=apt-fileless-c2&layer=endpoint")
	if got := strings.Count(rec.Body.String(), `"where":"SIGNAL_WHERE_ENDPOINT"`); got != 3 {
		t.Fatalf("endpoint signal count = %d, want 3: %s", got, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/signals?label=scenario=apt-fileless-c2&layer=cloud")
	if got := strings.Count(rec.Body.String(), `"where":"SIGNAL_WHERE_CLOUD"`); got != 2 {
		t.Fatalf("cloud signal count = %d, want 2: %s", got, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/incidents?label=scenario=apt-fileless-c2")
	if got := strings.Count(rec.Body.String(), `"id":"inc-`); got != 1 {
		t.Fatalf("incident count = %d, want 1: %s", got, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/metrics")
	for _, want := range []string{
		`"data_batches_appended":1`,
		`"events_ingested":1`,
		`"endpoint_signals_ingested":3`,
		`"cloud_signals_emitted":2`,
		`"signals_emitted":5`,
		`"incidents_created":1`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %s after retry: %s", want, rec.Body.String())
		}
	}
}

func TestUploadUpdatesRarityBaselineWithoutDuplicateAmplification(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	batch := httpDataBatch("rarity-batch-1", "agent-rarity", "host-rarity", nil, []*signalv1.Signal{{
		Id:           "sig-rarity-download",
		Name:         "download_by_lolbin",
		Where:        signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		BaseRisk:     50,
		GlobalRarity: 1,
		Labels:       labelsForScenario("rarity-append"),
		Entities: []*signalv1.EntityRef{{
			Kind: "container",
			Key:  "checkout-api",
		}},
	}})
	appendBatch(t, srv, batch)
	if got := st.RarityBaselineSnapshotForTenant("default").Count("container:checkout-api", "download_by_lolbin"); got != 1 {
		t.Fatalf("workload baseline count = %d, want 1", got)
	}
	appendBatch(t, srv, batch)
	if got := st.RarityBaselineSnapshotForTenant("default").Count("container:checkout-api", "download_by_lolbin"); got != 1 {
		t.Fatalf("workload baseline count after duplicate = %d, want 1", got)
	}
	rec := get(t, handler, "/api/v1/rarity-baseline?workload=container:checkout-api&signal=download_by_lolbin")
	for _, want := range []string{
		`"count":1`,
		`"container:checkout-api":{"download_by_lolbin":1}`,
		`"global":{"download_by_lolbin":1}`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("rarity baseline response missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestUploadIndexesSecurityDocuments(t *testing.T) {
	st, _ := store.Open("")
	indexer := &recordingIndexer{}
	_, err := ingestworker.NewProcessor(st, indexer).Process(context.Background(), httpDataBatch("batch-index", "agent-index", "host-index", []*eventv1.CanonicalEvent{{Id: "ev-index", Labels: labelsForScenario("apt-fileless-c2"), Behavior: "process.exec"}}, []*signalv1.Signal{
		endpointSignal("web_runtime_spawns_shell", "lin-index", false, processEntity("p-web")),
		endpointSignal("payload_dropped", "lin-index", false, fileEntity("/dev/shm/x.sh")),
		endpointSignal("reverse_shell_pattern", "lin-index", true, processEntity("p-bash"), socketEntity("10.66.0.99:443")),
	}))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	indexes := map[string]bool{}
	for _, doc := range indexer.docs {
		indexes[doc.Index] = true
	}
	for _, want := range []string{platformopensearch.EventsWriteAlias, platformopensearch.SignalsWriteAlias, platformopensearch.IncidentsWriteAlias, platformopensearch.EvidenceWriteAlias} {
		if !indexes[want] {
			t.Fatalf("indexed docs missing %s: %+v", want, indexer.docs)
		}
	}
}

func TestAgentsEventsResetAndRecompute(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	batch := httpDataBatch("", "agent-a", "host-a", []*eventv1.CanonicalEvent{{
		Id:       "ev-1",
		Labels:   labelsForScenario("apt-staged-drop"),
		Behavior: "process.exec",
		SubjectProc: &eventv1.ProcessRef{
			StableId: "p1",
			Binary:   "/bin/bash",
		},
		LineageId: "lin-a",
	}}, []*signalv1.Signal{
		endpointSignalForScenario("apt-staged-drop", "payload_dropped", "lin-a", false, fileEntity("/var/lib/app/plugins/helper")),
		endpointSignalForScenario("apt-staged-drop", "suspicious_exec_connect", "lin-b", false, fileEntity("/var/lib/app/plugins/helper"), socketEntity("10.66.0.99:443")),
	})
	appendBatch(t, srv, batch)

	rec := get(t, handler, "/api/v1/agents")
	if !strings.Contains(rec.Body.String(), "agent-a") {
		t.Fatalf("agents response missing agent-a: %s", rec.Body.String())
	}

	rec = get(t, handler, "/api/v1/events?label=scenario=apt-staged-drop&behavior=process.exec")
	if !strings.Contains(rec.Body.String(), "ev-1") {
		t.Fatalf("events response missing ev-1: %s", rec.Body.String())
	}

	rec = get(t, handler, "/api/v1/recompute?label=scenario=apt-staged-drop&disable=cloud.cross_lineage")
	if strings.Contains(rec.Body.String(), `"inc-`) {
		t.Fatalf("disabled cross-lineage recompute should not incident: %s", rec.Body.String())
	}

	st.DeleteByLabels(store.LabelSelector{"scenario": "apt-staged-drop"})
	if err := st.Save(); err != nil {
		t.Fatalf("save reset fixture: %v", err)
	}
	rec = get(t, handler, "/api/v1/events?label=scenario=apt-staged-drop")
	if rec.Body.String() != "[]\n" {
		t.Fatalf("events after reset = %s, want empty list", rec.Body.String())
	}
}

func TestSplitUploadRecomputesScenarioDerivedResults(t *testing.T) {
	st := &store.Store{}
	srv := newTestServer(st)
	handler := adminTestHandler(srv)
	scenario := "apt-staged-drop-stream"
	payload := fileEntity("/var/lib/app/plugins/helper")

	appendBatch(t, srv, httpDataBatch("", "", "", nil, []*signalv1.Signal{
		endpointSignalForScenario(scenario, "payload_dropped", "lin-drop", false, payload),
	}))
	rec := get(t, handler, "/api/v1/incidents?label=scenario="+scenario)
	if strings.Contains(rec.Body.String(), `"inc-`) {
		t.Fatalf("first split batch should not create incident: %s", rec.Body.String())
	}

	appendBatch(t, srv, httpDataBatch("", "", "", nil, []*signalv1.Signal{
		endpointSignalForScenario(scenario, "suspicious_exec_connect", "lin-connect", false, payload, socketEntity("10.66.0.99:443")),
	}))

	rec = get(t, handler, "/api/v1/signals?label=scenario="+scenario+"&layer=cloud")
	if got := strings.Count(rec.Body.String(), "dropped_payload_executed_and_connects"); got != 1 {
		t.Fatalf("cloud signal count = %d, want 1: %s", got, rec.Body.String())
	}

	rec = get(t, handler, "/api/v1/incidents?label=scenario="+scenario)
	body := rec.Body.String()
	if got := strings.Count(body, `"inc-`); got != 1 {
		t.Fatalf("incident count = %d, want 1: %s", got, body)
	}
	for _, want := range []string{"lin-drop", "lin-connect"} {
		if !strings.Contains(body, want) {
			t.Fatalf("incident missing lineage %s: %s", want, body)
		}
	}

	appendBatch(t, srv, httpDataBatch("", "", "", []*eventv1.CanonicalEvent{{Id: "noise-1", Labels: labelsForScenario(scenario), Behavior: "process.exec"}}, nil))
	rec = get(t, handler, "/api/v1/signals?label=scenario="+scenario+"&layer=cloud")
	if got := strings.Count(rec.Body.String(), "dropped_payload_executed_and_connects"); got != 1 {
		t.Fatalf("cloud signal duplicated after recompute, count = %d: %s", got, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/incidents?label=scenario="+scenario)
	if got := strings.Count(rec.Body.String(), `"inc-`); got != 1 {
		t.Fatalf("incident duplicated after recompute, count = %d: %s", got, rec.Body.String())
	}
}
