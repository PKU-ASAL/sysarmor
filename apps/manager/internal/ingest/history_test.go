package ingestworker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type recordingSearcher struct {
	requests []platformopensearch.SearchRequest
	docs     map[string][]json.RawMessage
}

func (s *recordingSearcher) Search(_ context.Context, request platformopensearch.SearchRequest) ([]json.RawMessage, error) {
	s.requests = append(s.requests, request)
	return s.docs[request.Index], nil
}

func TestOpenSearchHistoryReadsTenantScopeAndWindow(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.EventsReadAlias:  {json.RawMessage(`{"id":"ev-history","tenant_id":"tenant-a","labels":{"scenario":"a"},"@timestamp":"2026-07-12T00:05:00Z"}`)},
		platformopensearch.SignalsReadAlias: {json.RawMessage(`{"id":"sig-history","tenant_id":"tenant-a","name":"payload_dropped","where":"SIGNAL_WHERE_ENDPOINT","labels":{"scenario":"a"},"@timestamp":"2026-07-12T00:05:00Z"}`)},
	}}
	upper := time.Date(2026, 7, 12, 0, 10, 0, 0, time.UTC)
	events, signals, err := NewOpenSearchHistory(searcher).Read(context.Background(), "tenant-a", map[string]string{"scenario": "a"}, upper.Add(-15*time.Minute), upper)
	if err != nil || len(events) != 1 || len(signals) != 1 {
		t.Fatalf("Read() events=%d signals=%d error=%v", len(events), len(signals), err)
	}
	if len(searcher.requests) != 2 {
		t.Fatalf("requests = %d", len(searcher.requests))
	}
	for _, request := range searcher.requests {
		if request.Exact["tenant_id"] != "tenant-a" || request.Labels["scenario"] != "a" || request.TimeField != "@timestamp" || request.TimeFrom == "" || request.TimeTo == "" {
			t.Fatalf("unbounded request = %+v", request)
		}
	}
	if got := searcher.requests[1].Exact["where"]; got != "SIGNAL_WHERE_ENDPOINT" {
		t.Fatalf("signal history layer = %q, want endpoint enum", got)
	}
}

func TestOpenSearchHistoryRejectsDocumentsFromAnotherTenant(t *testing.T) {
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{
		platformopensearch.EventsReadAlias: {
			json.RawMessage(`{"id":"event-a","tenant_id":"tenant-a"}`),
			json.RawMessage(`{"id":"event-b","tenant_id":"tenant-b"}`),
			json.RawMessage(`{"id":"event-missing"}`),
		},
		platformopensearch.SignalsReadAlias: {
			json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","where":"SIGNAL_WHERE_ENDPOINT"}`),
			json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-b","where":"SIGNAL_WHERE_ENDPOINT"}`),
			json.RawMessage(`{"id":"signal-missing","where":"SIGNAL_WHERE_ENDPOINT"}`),
		},
	}}

	events, signals, err := NewOpenSearchHistory(searcher).Read(context.Background(), "tenant-a", nil, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].GetId() != "event-a" {
		t.Fatalf("events = %+v, want only tenant-a", events)
	}
	if len(signals) != 1 || signals[0].GetId() != "signal-a" {
		t.Fatalf("signals = %+v, want only tenant-a", signals)
	}
}

func TestProcessorCorrelatesStagedSignalsAcrossOpenSearchHistory(t *testing.T) {
	labels := map[string]string{"scenario": "staged-history"}
	searcher := &recordingSearcher{docs: map[string][]json.RawMessage{}}
	indexer := &recordingIndexer{}
	processor := NewProcessorWithHistory(&store.Store{}, indexer, NewOpenSearchHistory(searcher))

	mustProcess(t, processor, dataBatch("batch-drop", nil, []*signalv1.Signal{
		workerSignal("sig-drop", "payload_dropped", "lin-drop", labels, workerFile("/var/lib/app/plugins/helper")),
	}))
	searcher.docs[platformopensearch.SignalsReadAlias] = []json.RawMessage{json.RawMessage(
		`{"id":"sig-drop","tenant_id":"default","name":"payload_dropped","where":"SIGNAL_WHERE_ENDPOINT","labels":{"scenario":"staged-history"},"lineageId":"lin-drop","entities":[{"kind":"file","key":"/var/lib/app/plugins/helper","role":"object"}]}`,
	)}

	mustProcess(t, processor, dataBatch("batch-connect", nil, []*signalv1.Signal{
		workerSignal("sig-connect", "suspicious_exec_connect", "lin-connect", labels, workerFile("/var/lib/app/plugins/helper"), workerSocket("10.66.0.99:443")),
	}))
	cloud := lastDoc(indexer.docs, platformopensearch.SignalsWriteAlias)
	incident := lastDoc(indexer.docs, platformopensearch.IncidentsWriteAlias)
	if !strings.Contains(string(cloud.Body), `"name":"dropped_payload_executed_and_connects"`) || !strings.Contains(string(cloud.Body), `"crossLineage":true`) {
		t.Fatalf("cross-lineage cloud signal missing: %s", cloud.Body)
	}
	if incident.ID == "" {
		t.Fatal("cross-lineage incident document missing")
	}
}

func TestMergeAnalysisInputsDeduplicatesCurrentBatch(t *testing.T) {
	events := mergeEvents([]*eventv1.CanonicalEvent{{Id: "ev-a"}}, []*eventv1.CanonicalEvent{{Id: "ev-a"}, {Id: "ev-b"}})
	signals := mergeSignals([]*signalv1.Signal{{Id: "sig-a"}}, []*signalv1.Signal{{Id: "sig-a"}, {Id: "sig-b"}})
	if len(events) != 2 || len(signals) != 2 {
		t.Fatalf("events=%d signals=%d", len(events), len(signals))
	}
}
