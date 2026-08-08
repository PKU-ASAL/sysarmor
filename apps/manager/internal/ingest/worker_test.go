package ingestworker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	platformkafka "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/kafka"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestWorkerRejectsUnsupportedSchemaVersionToDLQ(t *testing.T) {
	batch := dataBatch("batch-schema", nil, nil)
	batch.SchemaVersion = "sysarmor.dataplane/v9"
	raw, err := protojson.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Value: raw}}}
	dlq := &stubProducer{}

	err = NewWorkerWithDLQ(consumer, NewProcessor(&store.Store{}, nil), dlq).Run(context.Background())

	if !errors.Is(err, context.Canceled) || consumer.committed != 1 || len(dlq.messages) != 1 {
		t.Fatalf("err=%v committed=%d dlq=%d", err, consumer.committed, len(dlq.messages))
	}
	var envelope deadLetterEnvelope
	if err := json.Unmarshal(dlq.messages[0].Value, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.FailureClass != "unsupported_schema_version" || envelope.FailureCode != "unsupported_schema_version" {
		t.Fatalf("envelope=%+v", envelope)
	}
}

func TestWorkerRejectsEmptySchemaVersionToDLQ(t *testing.T) {
	batch := dataBatch("batch-empty-schema", nil, nil)
	batch.SchemaVersion = ""
	raw, err := protojson.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Value: raw}}}
	dlq := &stubProducer{}
	err = NewWorkerWithDLQ(consumer, NewProcessor(&store.Store{}, nil), dlq).Run(context.Background())
	if !errors.Is(err, context.Canceled) || consumer.committed != 1 || len(dlq.messages) != 1 {
		t.Fatalf("err=%v committed=%d dlq=%d", err, consumer.committed, len(dlq.messages))
	}
}

type stubConsumer struct {
	messages  []platformkafka.Message
	committed int
}

func (c *stubConsumer) Fetch(context.Context) (platformkafka.Message, error) {
	if len(c.messages) == 0 {
		return platformkafka.Message{}, context.Canceled
	}
	msg := c.messages[0]
	c.messages = c.messages[1:]
	return msg, nil
}

func (c *stubConsumer) Commit(context.Context, platformkafka.Message) error {
	c.committed++
	return nil
}

func (c *stubConsumer) Close() error { return nil }

type stubProducer struct {
	err      error
	messages []platformkafka.Message
}

func (p *stubProducer) Append(_ context.Context, msg platformkafka.Message) error {
	p.messages = append(p.messages, msg)
	return p.err
}

func TestWorkerCommitsMalformedMessageAfterDLQPublish(t *testing.T) {
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Partition: 2, Offset: 7, Key: "bad", Value: []byte("{")}}}
	dlq := &stubProducer{}
	err := NewWorkerWithDLQ(consumer, NewProcessor(&store.Store{}, nil), dlq).Run(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if consumer.committed != 1 || len(dlq.messages) != 1 || dlq.messages[0].Topic != "raw.dlq" {
		t.Fatalf("committed=%d dlq=%+v", consumer.committed, dlq.messages)
	}
}

func TestWorkerDoesNotCommitWhenDLQPublishFails(t *testing.T) {
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Value: []byte("{")}}}
	dlq := &stubProducer{err: errors.New("dlq unavailable")}
	err := NewWorkerWithDLQ(consumer, NewProcessor(&store.Store{}, nil), dlq).Run(context.Background())
	if err == nil || consumer.committed != 0 {
		t.Fatalf("Run error=%v committed=%d", err, consumer.committed)
	}
}

func TestWorkerRejectsMissingBatchIdentityToDLQ(t *testing.T) {
	raw, err := protojson.Marshal(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{}})
	if err != nil {
		t.Fatal(err)
	}
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Value: raw}}}
	dlq := &stubProducer{}
	err = NewWorkerWithDLQ(consumer, NewProcessor(&store.Store{}, nil), dlq).Run(context.Background())
	if !errors.Is(err, context.Canceled) || consumer.committed != 1 || len(dlq.messages) != 1 {
		t.Fatalf("Run error=%v committed=%d dlq=%d", err, consumer.committed, len(dlq.messages))
	}
}

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

func TestWorkerConsumesKafkaUploadAndProcessesAfterCommit(t *testing.T) {
	raw, err := protojson.Marshal(&dataplanev1.DataBatch{
		SchemaVersion: schema.DataPlaneCurrent,
		Header:        &dataplanev1.BatchHeader{BatchId: "batch-worker", TenantId: "default", AgentId: "agent-worker", HostId: "host-worker"},
		Signals: []*dataplanev1.SignalFrame{{
			Signal: &signalv1.Signal{
				Id:     "sig-worker",
				Name:   "payload_dropped",
				Labels: map[string]string{"scenario": "worker-scenario"},
				Where:  signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer := &stubConsumer{messages: []platformkafka.Message{{Key: "default:agent-worker:batch-worker", Value: raw}}}
	st := &store.Store{}
	err = NewWorker(consumer, NewProcessor(st, nil)).Run(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled after first message", err)
	}
	if consumer.committed != 1 {
		t.Fatalf("committed = %d, want 1", consumer.committed)
	}
	if got := st.ListSignalsForTenant("default", store.LabelSelector{"scenario": "worker-scenario"}, "endpoint", false); len(got) != 1 {
		t.Fatalf("signals = %d, want 1", len(got))
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

func TestWorkerRetriesProcessingFailureWithoutCommit(t *testing.T) {
	raw, err := protojson.Marshal(dataBatch("batch-retry", []*eventv1.CanonicalEvent{{Id: "event-retry", Labels: map[string]string{"scenario": "retry"}}}, nil))
	if err != nil {
		t.Fatal(err)
	}
	consumer := &stubConsumer{messages: []platformkafka.Message{{Topic: "raw", Key: "retry", Value: raw}}}
	indexer := &failingIndexer{err: errors.New("opensearch unavailable")}
	err = NewWorker(consumer, NewProcessor(&store.Store{}, indexer)).Run(context.Background())
	if err == nil || consumer.committed != 0 || indexer.attempts != 3 {
		t.Fatalf("Run error=%v committed=%d attempts=%d", err, consumer.committed, indexer.attempts)
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
