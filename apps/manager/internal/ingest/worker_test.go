package ingestworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestIncidentDocumentIDUsesStableReportIdentity(t *testing.T) {
	first := &incidentv1.Incident{Summary: "first", TenantId: "tenant-a", CorrelationKey: "scenario=a", AnalysisVersion: "incident.v1"}
	second := &incidentv1.Incident{Summary: "updated", TenantId: "tenant-a", CorrelationKey: "scenario=a", AnalysisVersion: "incident.v1"}
	if IncidentDocumentID(first) != IncidentDocumentID(second) {
		t.Fatalf("report id changed with report content")
	}
}

func TestEndpointSignalDocumentIDIsStableAndAgentScoped(t *testing.T) {
	first := EndpointSignalDocumentID("default", "agent-a", "sig-1")
	if first == "" {
		t.Fatal("endpoint signal document ID is empty")
	}
	if first != EndpointSignalDocumentID("default", "agent-a", "sig-1") {
		t.Fatal("endpoint signal document ID is not deterministic")
	}
	if first == EndpointSignalDocumentID("default", "agent-b", "sig-1") {
		t.Fatal("endpoint signal document IDs collide across agents")
	}
	if first == EndpointSignalDocumentID("tenant-b", "agent-a", "sig-1") {
		t.Fatal("endpoint signal document IDs collide across tenants")
	}
}

func TestEventDocumentIDIsStableAndTenantScoped(t *testing.T) {
	first := EventDocumentID("tenant-a", "agent-a", "event-1")
	if first == "" || first != EventDocumentID("tenant-a", "agent-a", "event-1") {
		t.Fatalf("event ID is not stable: %q", first)
	}
	if first == EventDocumentID("tenant-b", "agent-a", "event-1") {
		t.Fatal("event ID collided across tenants")
	}
}

func TestCloudSignalDocumentIDIsStableAndTenantScoped(t *testing.T) {
	signal := &signalv1.Signal{Name: "cloud-signal", Where: signalv1.SignalWhere_SIGNAL_WHERE_CLOUD, Labels: map[string]string{"scenario": "shared"}}
	first := CloudSignalDocumentID("tenant-a", signal)
	if first == "" || first != CloudSignalDocumentID("tenant-a", signal) {
		t.Fatalf("cloud signal ID is not stable: %q", first)
	}
	if first == CloudSignalDocumentID("tenant-b", signal) {
		t.Fatal("cloud signal ID collided across tenants")
	}
}

func TestBatchDocumentsUsesScopedSignalID(t *testing.T) {
	batch := dataBatch("batch-signal-projection", nil, []*signalv1.Signal{
		workerSignal("sig-1", "payload_dropped", "lin-a", map[string]string{"scenario": "upgrade"}, workerFile("/tmp/payload")),
	})
	docs, err := batchDocuments(batch, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("signal projection documents = %d, want scoped index only", len(docs))
	}
	wantID := EndpointSignalDocumentID(batch.GetHeader().GetTenantId(), batch.GetHeader().GetAgentId(), "sig-1")
	if docs[0].ID != wantID {
		t.Fatalf("scoped signal document = %+v, want id %q", docs[0], wantID)
	}
}

func TestProcessorDoesNotDeleteCollidingLegacySignalIDs(t *testing.T) {
	first := dataBatch("batch-agent-a", nil, []*signalv1.Signal{
		workerSignal("sig-1", "payload_dropped", "lin-a", nil, workerFile("/tmp/a")),
	})
	second := dataBatch("batch-agent-b", nil, []*signalv1.Signal{
		workerSignal("sig-1", "payload_dropped", "lin-b", nil, workerFile("/tmp/b")),
	})
	second.Header.AgentId = "agent-b"
	projector := &phasedProjector{}
	processor := NewProcessor(&store.Store{}, projector)
	for _, batch := range []*dataplanev1.DataBatch{first, second} {
		if _, err := processor.Process(context.Background(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if len(projector.calls) != 2 || projector.calls[0][0].ID == projector.calls[1][0].ID {
		t.Fatalf("colliding legacy IDs were not independently scoped: %+v", projector.calls)
	}
}

type phasedProjector struct {
	calls  [][]platformopensearch.Document
	failAt int
}

func (p *phasedProjector) BulkIndex(_ context.Context, docs []platformopensearch.Document) error {
	p.calls = append(p.calls, append([]platformopensearch.Document(nil), docs...))
	if len(p.calls) == p.failAt {
		return errors.New("projection failed")
	}
	return nil
}

func TestProcessorWritesFormalIncidentIdentity(t *testing.T) {
	indexer := &recordingIndexer{}
	processor := NewProcessor(&store.Store{}, indexer)
	labels := map[string]string{"scenario": "formal-identity"}
	mustProcess(t, processor, dataBatch("batch-drop", nil, []*signalv1.Signal{
		workerSignal("sig-drop", "payload_dropped", "lin-drop", labels, workerFile("/tmp/payload")),
	}))
	mustProcess(t, processor, dataBatch("batch-connect", nil, []*signalv1.Signal{
		workerSignal("sig-connect", "suspicious_exec_connect", "lin-connect", labels, workerFile("/tmp/payload"), workerSocket("10.0.0.1:443")),
	}))
	doc := lastDoc(indexer.docs, "sysarmor-incidents-write")
	report := &incidentv1.Incident{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(doc.Body, report); err != nil {
		t.Fatal(err)
	}
	if report.GetTenantId() != "default" || report.GetCorrelationKey() != "scenario=formal-identity" || report.GetAnalysisVersion() != "incident.v1" {
		t.Fatalf("formal identity = %+v", report)
	}
	if report.GetLabels()["tenant_id"] != "" {
		t.Fatalf("legacy fields populated = %+v", report)
	}
}

func TestProcessorIndexesDerivedDocumentsWithStableIDs(t *testing.T) {
	st := &store.Store{}
	indexer := &recordingIndexer{}
	processor := NewProcessor(st, indexer)
	scenario := "staged-recompute"
	labels := map[string]string{"scenario": scenario}

	mustProcess(t, processor, dataBatch("batch-drop", nil, []*signalv1.Signal{
		workerSignal("sig-drop", "payload_dropped", "lin-drop", labels, workerFile("/var/lib/app/plugins/helper")),
	}))
	mustProcess(t, processor, dataBatch("batch-connect", nil, []*signalv1.Signal{
		workerSignal("sig-connect", "suspicious_exec_connect", "lin-connect", labels, workerFile("/var/lib/app/plugins/helper"), workerSocket("10.66.0.99:443")),
	}))
	firstSignalID := lastDocIDContaining(indexer.docs, "sysarmor-signals-write", "dropped_payload_executed_and_connects")
	firstIncidentID := lastDocID(indexer.docs, "sysarmor-incidents-write")
	if firstSignalID == "" || firstIncidentID == "" {
		t.Fatalf("missing derived docs: %+v", indexer.docs)
	}

	mustProcess(t, processor, dataBatch("batch-noise", []*eventv1.CanonicalEvent{{
		Id:       "ev-noise",
		Labels:   labels,
		Behavior: "process.exec",
	}}, nil))
	if got := lastDocIDContaining(indexer.docs, "sysarmor-signals-write", "dropped_payload_executed_and_connects"); got != firstSignalID {
		t.Fatalf("cloud signal document id = %q, want stable %q", got, firstSignalID)
	}
	if got := lastDocID(indexer.docs, "sysarmor-incidents-write"); got != firstIncidentID {
		t.Fatalf("incident document id = %q, want stable %q", got, firstIncidentID)
	}
}

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

type failingIndexer struct {
	err      error
	attempts int
}

func (i *failingIndexer) Index(context.Context, platformopensearch.Document) error {
	i.attempts++
	return i.err
}

func (i *failingIndexer) BulkIndex(context.Context, []platformopensearch.Document) error {
	i.attempts++
	return i.err
}

func TestProcessorReturnsIndexError(t *testing.T) {
	want := errors.New("opensearch unavailable")
	processor := NewProcessor(&store.Store{}, &failingIndexer{err: want})
	_, err := processor.Process(context.Background(), dataBatch("batch-index-error", []*eventv1.CanonicalEvent{{
		Id:     "event-index-error",
		Labels: map[string]string{"scenario": "index-error"},
	}}, nil))
	if !errors.Is(err, want) {
		t.Fatalf("Process() error = %v, want %v", err, want)
	}
}

func mustProcess(t *testing.T, processor *Processor, batch *dataplanev1.DataBatch) {
	t.Helper()
	if _, err := processor.Process(context.Background(), batch); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
}

func dataBatch(id string, events []*eventv1.CanonicalEvent, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	batch := &dataplanev1.DataBatch{
		SchemaVersion: schema.DataPlaneCurrent,
		Header:        &dataplanev1.BatchHeader{BatchId: id, TenantId: "default", AgentId: "agent-worker", HostId: "host-worker"},
	}
	for _, ev := range events {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{Event: ev})
	}
	for _, sig := range signals {
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{Signal: sig})
	}
	return batch
}

func workerSignal(id, name, lineage string, labels map[string]string, entities ...*signalv1.EntityRef) *signalv1.Signal {
	return &signalv1.Signal{
		Id:        id,
		Name:      name,
		Where:     signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		LineageId: lineage,
		Labels:    labels,
		Entities:  entities,
	}
}

func workerFile(path string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "file", Key: "file:" + path, Role: "object"}
}

func workerSocket(addr string) *signalv1.EntityRef {
	return &signalv1.EntityRef{Kind: "socket", Key: "socket:" + addr, Role: "object"}
}

func lastDocID(docs []platformopensearch.Document, index string) string {
	for i := len(docs) - 1; i >= 0; i-- {
		if docs[i].Index == index {
			return docs[i].ID
		}
	}
	return ""
}

func lastDoc(docs []platformopensearch.Document, index string) platformopensearch.Document {
	for i := len(docs) - 1; i >= 0; i-- {
		if docs[i].Index == index {
			return docs[i]
		}
	}
	return platformopensearch.Document{}
}

func lastDocIDContaining(docs []platformopensearch.Document, index, needle string) string {
	for i := len(docs) - 1; i >= 0; i-- {
		if docs[i].Index == index && strings.Contains(string(docs[i].Body), needle) {
			return docs[i].ID
		}
	}
	return ""
}

type recordingTelemetryBatches struct {
	claim   ports.TelemetryClaim
	token   string
	commits int
}

type fixedDetectionPolicies struct {
	policy domainpolicy.Policy
	calls  int
}

type fixedRarityReader struct{}

func (fixedRarityReader) Rarity(context.Context, tenant.ID) (identity.RarityBaseline, error) {
	return identity.RarityBaseline{WorkloadCounts: map[string]map[string]uint64{}}, nil
}

func (reader *fixedDetectionPolicies) Effective(context.Context, tenant.ID, identity.AgentID) (domainpolicy.Policy, error) {
	reader.calls++
	return reader.policy, nil
}

func (b *recordingTelemetryBatches) Claim(context.Context, string, string, time.Duration) (ports.TelemetryClaim, string, error) {
	return b.claim, b.token, nil
}

func (b *recordingTelemetryBatches) Commit(context.Context, ports.TelemetryBatchDelta) error {
	b.commits++
	return nil
}

func (*recordingTelemetryBatches) Abandon(context.Context, string, string, string) error { return nil }

func TestProcessorUsesTelemetryBatchPortForDuplicateClaim(t *testing.T) {
	batches := &recordingTelemetryBatches{claim: ports.TelemetryDuplicate, token: "claim-token"}
	processor := NewProcessor(&store.Store{}, &recordingIndexer{})
	processor.SetTelemetryBatches(batches)

	result, err := processor.Process(context.Background(), dataBatch("duplicate", nil, nil))
	if err != nil || !result.Duplicate {
		t.Fatalf("Process() result=%+v error=%v", result, err)
	}
	if batches.commits != 0 {
		t.Fatalf("commits = %d, want 0", batches.commits)
	}
}

func TestRemoteProcessorDoesNotRegisterAgentAgain(t *testing.T) {
	state := &store.Store{}
	processor := NewProcessorWithHistory(state, &recordingIndexer{}, NewOpenSearchHistory(nil))
	if _, err := processor.Process(context.Background(), dataBatch("remote-agent", nil, nil)); err != nil {
		t.Fatal(err)
	}
	if len(state.Agents) != 0 {
		t.Fatalf("agents = %+v, worker must not duplicate gateway registration", state.Agents)
	}
}

func TestRemoteProcessorDoesNotSaveLegacySnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-state.json")
	state, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	batches := &recordingTelemetryBatches{claim: ports.TelemetryClaimed, token: "claim-token"}
	processor := NewProcessorWithHistory(state, &recordingIndexer{}, NewOpenSearchHistory(nil))
	processor.SetTelemetryBatches(batches)
	if _, err := processor.Process(context.Background(), dataBatch("remote-save", nil, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("legacy snapshot was written: %v", err)
	}
}

func TestProcessorReadsDetectionPolicyThroughPort(t *testing.T) {
	reader := &fixedDetectionPolicies{policy: domainpolicy.Policy{Document: []byte(`{"cloud_rules":["rule-a"]}`)}}
	processor := NewProcessorWithHistory(&store.Store{}, &recordingIndexer{}, NewOpenSearchHistory(nil))
	processor.SetDetectionPolicies(reader)
	policy, err := processor.effectiveDetectionPolicyForAgent(context.Background(), store.AgentIdentity{TenantID: "tenant-a", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if reader.calls != 1 || len(policy.GetCloudRules()) != 1 || policy.GetCloudRules()[0] != "rule-a" {
		t.Fatalf("calls=%d policy=%+v", reader.calls, policy)
	}
}

func TestRemoteProcessorDoesNotRequireLegacyStore(t *testing.T) {
	batches := &recordingTelemetryBatches{claim: ports.TelemetryClaimed, token: "claim-token"}
	policies := &fixedDetectionPolicies{policy: domainpolicy.Policy{Document: []byte(`{}`)}}
	processor := NewRemoteProcessor(&recordingIndexer{}, NewOpenSearchHistory(nil), fixedRarityReader{}, batches, policies)
	if _, err := processor.Process(context.Background(), dataBatch("storeless", nil, nil)); err != nil {
		t.Fatal(err)
	}
}
