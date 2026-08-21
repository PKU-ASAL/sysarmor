package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestBatchProjectorMapsDomainProjectionToDocuments(t *testing.T) {
	indexer := &documentProjectorStub{}
	projector := NewBatchProjector(indexer)
	projection := ports.BatchProjection{
		TenantID: tenant.ID("tenant-a"), AgentID: identity.AgentID("agent-a"), ObservedAt: time.Unix(1, 0).UTC(),
		Events:  []ports.ObservedEvent{{Event: domaintelemetry.Event{ID: "event-a", TenantID: "tenant-a"}}},
		Signals: []ports.ObservedSignal{{Signal: domaintelemetry.Signal{ID: "signal-a", Where: domaintelemetry.SignalWhereEndpoint}}},
	}

	err := projector.Project(context.Background(), projection)

	if err != nil || len(indexer.documents) != 2 {
		t.Fatalf("documents=%+v err=%v", indexer.documents, err)
	}
	if indexer.documents[0].ID == "" || indexer.documents[1].ID == "" {
		t.Fatalf("document ids=%q,%q", indexer.documents[0].ID, indexer.documents[1].ID)
	}
	var body map[string]any
	if err := json.Unmarshal(indexer.documents[0].Body, &body); err != nil || body["tenant_id"] != "tenant-a" {
		t.Fatalf("body=%s err=%v", indexer.documents[0].Body, err)
	}
}

func TestBatchProjectorPreservesCloudSignalIdentity(t *testing.T) {
	indexer := &documentProjectorStub{}
	projection := ports.BatchProjection{
		TenantID: tenant.ID("tenant-a"), AgentID: identity.AgentID("agent-a"), ObservedAt: time.Unix(1, 0).UTC(),
		Signals: []ports.ObservedSignal{{Signal: domaintelemetry.Signal{ID: "cloud-a", Where: domaintelemetry.SignalWhereCloud}}},
	}

	if err := NewBatchProjector(indexer).Project(context.Background(), projection); err != nil {
		t.Fatal(err)
	}
	if len(indexer.documents) != 1 || indexer.documents[0].ID != CloudSignalDocumentID("tenant-a", projection.Signals[0].Signal) {
		t.Fatalf("documents=%+v", indexer.documents)
	}
}

func TestBatchProjectorUsesCloudSignalObservedTime(t *testing.T) {
	indexer := &documentProjectorStub{}
	observedAt := time.Unix(20, 0).UTC()
	projection := ports.BatchProjection{
		TenantID: tenant.ID("tenant-a"), ObservedAt: time.Unix(30, 0).UTC(),
		CloudSignals: []ports.ObservedSignal{{
			Signal:     domaintelemetry.Signal{ID: "cloud-a", Where: domaintelemetry.SignalWhereCloud},
			ObservedAt: observedAt,
		}},
	}

	if err := NewBatchProjector(indexer).Project(context.Background(), projection); err != nil {
		t.Fatal(err)
	}
	if len(indexer.documents) != 1 {
		t.Fatalf("documents=%+v", indexer.documents)
	}
	var body map[string]any
	if err := json.Unmarshal(indexer.documents[0].Body, &body); err != nil || body["@timestamp"] != observedAt.Format(time.RFC3339Nano) {
		t.Fatalf("body=%s err=%v", indexer.documents[0].Body, err)
	}
}

func TestDecodeHistoryPreservesSignalObservedTime(t *testing.T) {
	observedAt := time.Unix(20, 0).UTC()
	raw := json.RawMessage(`{"id":"signal-a","where":"SIGNAL_WHERE_ENDPOINT","stage":"SIGNAL_STAGE_CANDIDATE","detectorKind":"DETECTOR_KIND_RULE","@timestamp":"` + observedAt.Format(time.RFC3339Nano) + `"}`)

	history, err := decodeHistory(nil, []json.RawMessage{raw})

	if err != nil || len(history.Signals) != 1 || !history.Signals[0].ObservedAt.Equal(observedAt) {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestBatchProjectorDecoratesIncidentAndEvidence(t *testing.T) {
	indexer := &documentProjectorStub{}
	projection := ports.BatchProjection{
		TenantID: tenant.ID("tenant-a"), ObservedAt: time.Unix(1, 0).UTC(),
		Incidents: []domaintelemetry.Incident{{ID: "incident-a", TenantID: "tenant-a", Evidence: &domaintelemetry.EvidenceSubgraph{}}},
	}

	if err := NewBatchProjector(indexer).Project(context.Background(), projection); err != nil {
		t.Fatal(err)
	}
	if len(indexer.documents) != 2 {
		t.Fatalf("documents=%+v", indexer.documents)
	}
	for _, document := range indexer.documents {
		var body map[string]any
		if err := json.Unmarshal(document.Body, &body); err != nil || body["tenant_id"] != "tenant-a" || body["@timestamp"] == nil {
			t.Fatalf("document=%s err=%v", document.Body, err)
		}
	}
}

func TestBatchProjectorClassifiesPermanentOpenSearchFailure(t *testing.T) {
	source := ports.RawMessage{Topic: "raw", Value: []byte("payload")}
	indexer := &documentProjectorStub{err: &platformopensearch.ProjectionError{Class: platformopensearch.ErrorPermanent, Cause: errors.New("bad document")}}

	err := NewBatchProjector(indexer).Project(context.Background(), ports.BatchProjection{Source: source})

	assertPermanentEnvelope(t, err, "permanent_projection")
}

func assertPermanentEnvelope(t *testing.T, err error, class string) {
	t.Helper()
	var permanent ports.PermanentError
	if !errors.As(err, &permanent) || permanent.Message == nil {
		t.Fatalf("error=%v", err)
	}
	var envelope struct {
		FailureClass string `json:"failure_class"`
	}
	if decodeErr := json.Unmarshal(permanent.Message.Value, &envelope); decodeErr != nil || envelope.FailureClass != class {
		t.Fatalf("envelope=%+v decodeErr=%v", envelope, decodeErr)
	}
}

type documentProjectorStub struct {
	documents []ports.SearchDocument
	err       error
}

func (stub *documentProjectorStub) BulkIndex(_ context.Context, documents []ports.SearchDocument) error {
	stub.documents = documents
	return stub.err
}
