package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestAnalysisSignalsDecodeOnlyAuthenticatedTenant(t *testing.T) {
	searcher := &analysisPageSearcherStub{pages: []SearchPage{{Hits: []SearchHit{
		{Source: json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","name":"exec","where":"SIGNAL_WHERE_ENDPOINT","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE"}`), Sort: []any{"a"}},
		{Source: json.RawMessage(`{"id":"signal-b","tenant_id":"tenant-b","name":"other","where":"SIGNAL_WHERE_ENDPOINT","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE"}`), Sort: []any{"b"}},
	}}}}
	reader := NewAnalysisSignalReader(searcher)
	values, err := reader.Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{Layer: "endpoint"})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ID != "signal-a" || searcher.requests[0].Exact["tenant_id"] != "tenant-a" {
		t.Fatalf("signals = %+v, requests = %+v", values, searcher.requests)
	}
}

func TestAnalysisSignalsReadsEveryPage(t *testing.T) {
	first := make([]SearchHit, analysisPageSize)
	for index := range first {
		first[index] = SearchHit{Source: json.RawMessage(fmt.Sprintf(`{"id":"signal-%d","tenant_id":"tenant-a","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE"}`, index)), Sort: []any{index}}
	}
	searcher := &analysisPageSearcherStub{pages: []SearchPage{
		{Hits: first}, {Hits: []SearchHit{{Source: json.RawMessage(`{"id":"critical","tenant_id":"tenant-a","stage":"SIGNAL_STAGE_CONCLUSION","detector_kind":"DETECTOR_KIND_RULE"}`), Sort: []any{analysisPageSize}}}},
	}}
	values, err := NewAnalysisSignalReader(searcher).Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{})
	if err != nil || len(values) != analysisPageSize+1 || len(searcher.requests) != 2 || len(searcher.requests[1].SearchAfter) == 0 {
		t.Fatalf("signals = %d, requests = %+v, error = %v", len(values), searcher.requests, err)
	}
}

func TestAnalysisSignalsRejectMalformedDocuments(t *testing.T) {
	for name, document := range map[string]json.RawMessage{
		"invalid json":   json.RawMessage(`{`),
		"non object":     json.RawMessage(`[]`),
		"missing tenant": json.RawMessage(`{"id":"signal-a"}`),
		"invalid tenant": json.RawMessage(`{"tenant_id":7}`),
		"invalid signal": json.RawMessage(`{"tenant_id":"tenant-a","base_risk":"bad","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE"}`),
	} {
		t.Run(name, func(t *testing.T) {
			searcher := &analysisPageSearcherStub{pages: []SearchPage{{Hits: []SearchHit{{Source: document, Sort: []any{"a"}}}}}}
			_, err := NewAnalysisSignalReader(searcher).Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{})
			if err == nil {
				t.Fatal("malformed signal accepted")
			}
		})
	}
}

func TestAnalysisSignalsFiltersMismatchedLabels(t *testing.T) {
	searcher := &analysisPageSearcherStub{pages: []SearchPage{{Hits: []SearchHit{
		{Source: json.RawMessage(`{"id":"wrong","tenant_id":"tenant-a","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE","labels":{"scenario":"other"}}`), Sort: []any{"a"}},
		{Source: json.RawMessage(`{"id":"right","tenant_id":"tenant-a","stage":"SIGNAL_STAGE_CANDIDATE","detector_kind":"DETECTOR_KIND_RULE","labels":{"scenario":"one"}}`), Sort: []any{"b"}},
	}}}}
	values, err := NewAnalysisSignalReader(searcher).Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{Labels: map[string]string{"scenario": "one"}})
	if err != nil || len(values) != 1 || values[0].ID != "right" {
		t.Fatalf("values = %+v, error = %v", values, err)
	}
}

func TestAnalysisSignalsClassifiesSearchFailureAsRetryable(t *testing.T) {
	searcher := &analysisPageSearcherStub{err: errors.New("opensearch unavailable")}
	_, err := NewAnalysisSignalReader(searcher).Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{})
	if failure.KindOf(err) != failure.RetryableDependency {
		t.Fatalf("failure kind = %v, error = %v", failure.KindOf(err), err)
	}
}

func TestAnalysisSignalsRejectsMalformedRequestedLabels(t *testing.T) {
	searcher := &analysisPageSearcherStub{pages: []SearchPage{{Hits: []SearchHit{{
		Source: json.RawMessage(`{"id":"signal-a","tenant_id":"tenant-a","labels":7}`), Sort: []any{"a"},
	}}}}}
	_, err := NewAnalysisSignalReader(searcher).Signals(context.Background(), tenant.ID("tenant-a"), ports.AnalysisSignalFilter{Labels: map[string]string{"scenario": "one"}})
	if err == nil {
		t.Fatal("malformed labels accepted")
	}
}

type analysisPageSearcherStub struct {
	requests []SearchRequest
	pages    []SearchPage
	err      error
}

func (stub *analysisPageSearcherStub) SearchPage(_ context.Context, request SearchRequest) (SearchPage, error) {
	stub.requests = append(stub.requests, request)
	if stub.err != nil {
		return SearchPage{}, stub.err
	}
	index := len(stub.requests) - 1
	if index >= len(stub.pages) {
		return SearchPage{}, nil
	}
	return stub.pages[index], nil
}
