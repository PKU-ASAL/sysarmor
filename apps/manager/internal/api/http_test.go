package managerapi

import (
	"context"
	"encoding/json"
	"fmt"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	identityhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

var testBatchSequence uint64

type recordingIndexer struct {
	docs []platformopensearch.Document
}

func (i *recordingIndexer) Index(_ context.Context, doc platformopensearch.Document) error {
	i.docs = append(i.docs, doc)
	return nil
}

func (i *recordingIndexer) BulkIndex(_ context.Context, docs []platformopensearch.Document) error {
	i.docs = append(i.docs, docs...)
	return nil
}

type fakeSearcher struct {
	docs map[string][]json.RawMessage
	last platformopensearch.SearchRequest
}

func (s fakeSearcher) Search(_ context.Context, search platformopensearch.SearchRequest) ([]json.RawMessage, error) {
	return append([]json.RawMessage(nil), s.docs[search.Index]...), nil
}

func newTestServer(st *store.Store) *Server {
	server := NewServer(st)
	setTestIdentityApplication(server, st)
	setTestTelemetryApplication(server, st)
	setTestStoreOverviewApplication(server, st)
	return server
}

func setTestIdentityApplication(server *Server, st *store.Store) {
	queries := testIdentityQuery(st)
	server.SetIdentityApplication(queries, PolicyRequestContext)
	server.SetIdentityRoutes(identityhttp.NewHandler(identityhttp.Options{Query: queries, Resolve: PolicyRequestContext}))
}

func testIdentityQuery(st *store.Store) *testIdentityQueries {
	query := &testIdentityQueries{store: st, health: map[domainidentity.AgentID]domainidentity.Health{}}
	for _, agent := range st.Agents {
		tenantID, _ := tenant.NewID(agent.Normalized().TenantID)
		query.agents = append(query.agents, domainidentity.AgentView{Agent: domainidentity.Agent{TenantID: tenantID, ID: domainidentity.AgentID(agent.AgentID)}})
	}
	for _, health := range st.Health {
		tenantID, _ := tenant.NewID(health.TenantID)
		document, _ := json.Marshal(health)
		query.health[domainidentity.AgentID(health.AgentID)] = domainidentity.Health{TenantID: tenantID, AgentID: domainidentity.AgentID(health.AgentID), HostID: health.HostID, Status: health.Status, Scope: domainidentity.Scope{Type: health.Scope.Type, Selector: health.Scope.Selector}, ObservedAt: health.ObservedAt, Document: document}
	}
	for index := range query.agents {
		health, ok := query.health[query.agents[index].Agent.ID]
		query.agents[index].Health, query.agents[index].HasHealth = health, ok
	}
	return query
}

type testIdentityQueries struct {
	store    *store.Store
	overview domainidentity.AgentOverview
	metrics  domainidentity.Metrics
	agents   []domainidentity.AgentView
	health   map[domainidentity.AgentID]domainidentity.Health
	err      error
}

func (q *testIdentityQueries) Rarity(_ context.Context, request managerapp.RequestContext) (domainidentity.RarityBaseline, error) {
	if q.err != nil || q.store == nil {
		return domainidentity.RarityBaseline{}, q.err
	}
	value := q.store.RarityByTenant[request.Actor.TenantID.String()]
	return domainidentity.RarityBaseline{WorkloadCounts: value.Snapshot().WorkloadCounts}, nil
}

func (q *testIdentityQueries) Metrics(_ context.Context, request managerapp.RequestContext) (domainidentity.Metrics, error) {
	if q.err != nil || q.store == nil {
		return q.metrics, q.err
	}
	value := q.store.MetricsByTenant[request.Actor.TenantID.String()]
	return domainidentity.Metrics{DataBatchesAppended: value.DataBatchesAppended, EventsIngested: value.EventsIngested, EndpointSignalsIngested: value.EndpointSignalsIngested, CloudSignalsEmitted: value.CloudSignalsEmitted, SignalsEmitted: value.SignalsEmitted, IncidentsCreated: value.IncidentsCreated, DuplicateEvents: value.DuplicateEvents}, nil
}

func (q *testIdentityQueries) AgentOverview(_ context.Context, request managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	if q.err != nil {
		return domainidentity.AgentOverview{}, q.err
	}
	if q.store == nil {
		return q.overview, nil
	}
	result := domainidentity.AgentOverview{}
	for _, agent := range q.agents {
		if agent.Agent.TenantID != request.Actor.TenantID {
			continue
		}
		result.Total++
		health, ok := q.health[agent.Agent.ID]
		if !ok {
			result.Offline++
			continue
		}
		var document struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(health.Document, &document)
		switch document.Status {
		case "ok", "healthy":
			result.Online++
		case "degraded":
			result.Degraded++
		default:
			result.Offline++
		}
	}
	return result, nil
}

func (q *testIdentityQueries) ListHealth(_ context.Context, request managerapp.RequestContext, query identityapp.ListHealthQuery) (identityapp.ListHealthResult, error) {
	result := make([]domainidentity.Health, 0)
	values := q.health
	if q.store != nil {
		values = testIdentityQuery(q.store).health
	}
	for _, value := range values {
		if value.TenantID == request.Actor.TenantID && (query.Filter.AgentID == "" || string(value.AgentID) == query.Filter.AgentID) {
			result = append(result, value)
		}
	}
	return identityapp.ListHealthResult{Health: result}, q.err
}

func (q *testIdentityQueries) ListSessions(_ context.Context, request managerapp.RequestContext, query identityapp.ListSessionsQuery) (identityapp.ListSessionsResult, error) {
	result := make([]domainidentity.Session, 0)
	if q.store != nil {
		for _, value := range q.store.AgentSessions {
			if value.TenantID == request.Actor.TenantID.String() && (query.Filter.AgentID == "" || value.AgentID == query.Filter.AgentID) {
				result = append(result, domainidentity.Session{TenantID: request.Actor.TenantID, ID: value.SessionID, AgentID: domainidentity.AgentID(value.AgentID), StartedAt: value.StartedAt, LastSeenAt: value.LastSeenAt, LastDataSeenAt: value.LastDataSeenAt, LastControlSeenAt: value.LastControlSeenAt, ClosedAt: value.ClosedAt, LastAckCursor: value.LastAckCursor, DataTransport: value.DataTransport, ControlTransport: value.ControlTransport, Status: value.Status})
			}
		}
	}
	return identityapp.ListSessionsResult{Sessions: result}, q.err
}

func (q *testIdentityQueries) Resume(ctx context.Context, request managerapp.RequestContext, agentID string) (identityapp.ResumeResult, error) {
	values, err := q.ListSessions(ctx, request, identityapp.ListSessionsQuery{Filter: domainidentity.SessionFilter{AgentID: agentID}})
	result := identityapp.ResumeResult{TenantID: request.Actor.TenantID.String(), AgentID: agentID}
	if len(values.Sessions) > 0 {
		result.SessionID, result.ResumeCursor = values.Sessions[0].ID, values.Sessions[0].LastAckCursor
	}
	return result, err
}

func (q *testIdentityQueries) ListAgents(_ context.Context, request managerapp.RequestContext, query identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error) {
	agents := q.agents
	if q.store != nil {
		agents = testIdentityQuery(q.store).agents
	}
	result := make([]domainidentity.AgentView, 0, len(agents))
	for _, agent := range agents {
		if agent.Agent.TenantID != request.Actor.TenantID || query.Filter.ScopeType != "" && agent.Health.Scope.Type != query.Filter.ScopeType || query.Filter.ScopeSelector != "" && agent.Health.Scope.Selector != query.Filter.ScopeSelector || query.Filter.HealthStatus != "" && agent.Health.Status != query.Filter.HealthStatus {
			continue
		}
		result = append(result, agent)
	}
	return identityapp.ListAgentsResult{Agents: result}, q.err
}
func (q *testIdentityQueries) GetHealth(_ context.Context, _ managerapp.RequestContext, id domainidentity.AgentID) (domainidentity.Health, error) {
	if q.err != nil {
		return domainidentity.Health{}, q.err
	}
	v, ok := q.health[id]
	if !ok && q.store != nil {
		for _, health := range q.store.Health {
			if health.AgentID == string(id) {
				tenantID, _ := tenant.NewID(health.TenantID)
				document, _ := json.Marshal(health)
				v, ok = domainidentity.Health{TenantID: tenantID, AgentID: id, Document: document}, true
				break
			}
		}
	}
	if !ok {
		return domainidentity.Health{}, failure.New(failure.NotFound, "health not found")
	}
	return v, nil
}

func seedTenantTelemetry(t *testing.T, st *store.Store, tenantID, batchID string, metrics store.Metrics, signals []*signalv1.Signal) {
	t.Helper()
	claim, token, err := st.ClaimTelemetryBatch(context.Background(), tenantID, batchID, time.Minute)
	if err != nil || claim != store.BatchClaimed {
		t.Fatalf("claim=%v err=%v", claim, err)
	}
	baseline := rarity.Baseline{}
	baseline.Observe(signals)
	if err := st.CommitTelemetryBatch(context.Background(), store.TelemetryBatchDelta{TenantID: tenantID, BatchID: batchID, ClaimToken: token, Metrics: metrics, Rarity: baseline}); err != nil {
		t.Fatal(err)
	}
}

func appendBatch(t *testing.T, srv *Server, batch *dataplanev1.DataBatch) {
	t.Helper()
	_ = appendBatchAndAck(t, srv, batch)
}

func appendBatchAndAck(t *testing.T, srv *Server, batch *dataplanev1.DataBatch) *dataplanev1.DataAck {
	t.Helper()
	if batch.Header == nil {
		batch.Header = &dataplanev1.BatchHeader{AgentId: "agent-a", HostId: "host-a", TenantId: "default"}
	}
	if batch.Header.BatchId == "" {
		batch.Header.BatchId = fmt.Sprintf("test-batch-%d", atomic.AddUint64(&testBatchSequence, 1))
	}
	if batch.Header.AgentId == "" {
		batch.Header.AgentId = "agent-a"
	}
	if batch.Header.HostId == "" {
		batch.Header.HostId = "host-a"
	}
	if batch.Header.TenantId == "" {
		batch.Header.TenantId = "default"
	}
	st, ok := srv.store.(*store.Store)
	if !ok {
		t.Fatalf("test server store type = %T, want *store.Store", srv.store)
	}
	duplicate := isDuplicateTestBatch(st, batch)
	st.RecordDataBatchAppend(store.AgentIdentityFromDataBatch(batch), batch.GetHeader().GetBatchId(), "grpc", time.Now().UTC())
	if err := st.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	acceptedEvents := 0
	acceptedSignals := 0
	if !duplicate {
		result, err := ingestworker.NewProcessor(st, nil).Process(context.Background(), batch)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		acceptedEvents = result.AcceptedEvents
		acceptedSignals = result.AcceptedSignals
	}
	status := dataplanev1.DataAck_STATUS_ACCEPTED
	message := "accepted"
	if duplicate {
		status = dataplanev1.DataAck_STATUS_DUPLICATE
		message = "duplicate"
	}
	return &dataplanev1.DataAck{
		BatchId:         batch.GetHeader().GetBatchId(),
		Accepted:        true,
		Status:          status,
		Message:         message,
		ReasonCode:      message,
		CommittedCursor: batch.GetHeader().GetBatchId(),
		ServerTime:      time.Now().UTC().Format(time.RFC3339Nano),
		AcceptedEvents:  uint64(acceptedEvents),
		AcceptedSignals: uint64(acceptedSignals),
		ContractVersion: "dataplane.v1",
	}
}

func isDuplicateTestBatch(st *store.Store, batch *dataplanev1.DataBatch) bool {
	header := batch.GetHeader()
	if header.GetBatchId() == "" {
		return false
	}
	for _, session := range st.ListAgentSessions(header.GetTenantId(), header.GetAgentId()) {
		if session.LastAckCursor == header.GetBatchId() {
			return true
		}
	}
	return false
}

func httpDataBatch(batchID, agentID, hostID string, events []*eventv1.CanonicalEvent, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	batch := &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{BatchId: batchID, AgentId: agentID, HostId: hostID, TenantId: "default"},
	}
	for _, ev := range events {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{Event: ev})
	}
	for _, sig := range signals {
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{Signal: sig})
	}
	return batch
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = withTestPrincipal(req, "test-viewer", "default", "viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d body=%s", path, rec.Code, rec.Body.String())
	}
	return rec
}

func endpointSignal(name, lineage string, terminal bool, entities ...*signalv1.EntityRef) *signalv1.Signal {
	return endpointSignalForScenario("apt-fileless-c2", name, lineage, terminal, entities...)
}

func endpointSignalForScenario(scenario, name, lineage string, terminal bool, entities ...*signalv1.EntityRef) *signalv1.Signal {
	return &signalv1.Signal{
		Name:         name,
		Where:        signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		BaseRisk:     50,
		GlobalRarity: 1,
		LineageId:    lineage,
		Terminal:     terminal,
		Entities:     entities,
		Labels:       labelsForScenario(scenario),
	}
}

func labelsForScenario(scenario string) map[string]string {
	return map[string]string{"scenario": scenario}
}

func processEntity(key string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "process", Key: key, Role: "subject"}
}

func fileEntity(key string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "file", Key: "file:" + key, Role: "object"}
}

func socketEntity(key string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "socket", Key: "socket:" + key, Role: "object"}
}
