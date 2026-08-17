package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	historyPageSize      = 1000
	historyDocumentLimit = 100_000
)

type OpenSearchHistory struct {
	searcher platformopensearch.PageSearcher
}

func NewOpenSearchHistory(searcher platformopensearch.PageSearcher) *OpenSearchHistory {
	return &OpenSearchHistory{searcher: searcher}
}

func (history *OpenSearchHistory) Read(ctx context.Context, tenantID tenant.ID, labels map[string]string, from, to time.Time) (ports.HistorySnapshot, error) {
	if history == nil || history.searcher == nil {
		return ports.HistorySnapshot{}, nil
	}
	request := historyRequest(platformopensearch.EventsReadAlias, tenantID, labels, from, to)
	events, err := readHistoryDocuments(ctx, history.searcher, request, historyDocumentLimit)
	if err != nil {
		return ports.HistorySnapshot{}, fmt.Errorf("read event history: %w", err)
	}
	request.Index = platformopensearch.SignalsReadAlias
	request.Exact["where"] = "SIGNAL_WHERE_ENDPOINT"
	signals, err := readHistoryDocuments(ctx, history.searcher, request, historyDocumentLimit)
	if err != nil {
		return ports.HistorySnapshot{}, fmt.Errorf("read signal history: %w", err)
	}
	return decodeHistory(filterTenantDocuments(events, tenantID.String()), filterTenantDocuments(signals, tenantID.String()))
}

func readHistoryDocuments(ctx context.Context, searcher platformopensearch.PageSearcher, request platformopensearch.SearchRequest, limit int) ([]json.RawMessage, error) {
	if limit <= 0 {
		return nil, nil
	}
	request.SortField = "_id"
	result := make([]json.RawMessage, 0, min(limit, historyPageSize))
	scanned := 0
	for pageNumber := 0; ; pageNumber++ {
		probingOverflow := scanned == limit
		request.Size = 1
		if !probingOverflow {
			request.Size = min(historyPageSize, limit-scanned)
		}
		page, err := searcher.SearchPage(ctx, request)
		if err != nil {
			return nil, fmt.Errorf("search history page %d: %w", pageNumber, err)
		}
		hits := page.Hits[:min(len(page.Hits), request.Size)]
		if probingOverflow && len(hits) > 0 {
			return nil, fmt.Errorf("history exceeds document limit %d", limit)
		}
		scanned += len(hits)
		for _, hit := range hits {
			if len(hit.Source) > 0 {
				result = append(result, hit.Source)
			}
		}
		if len(page.Hits) < request.Size {
			return result, nil
		}
		if len(page.Hits[len(page.Hits)-1].Sort) == 0 {
			return nil, fmt.Errorf("history page %d has no sort cursor", pageNumber)
		}
		request.SearchAfter = page.Hits[len(page.Hits)-1].Sort
	}
}

func historyRequest(index string, tenantID tenant.ID, labels map[string]string, from, to time.Time) platformopensearch.SearchRequest {
	return platformopensearch.SearchRequest{
		Index: index, Labels: cloneStringMap(labels), Exact: map[string]string{"tenant_id": tenantID.String()},
		TimeField: "@timestamp", TimeFrom: from.UTC().Format(time.RFC3339Nano), TimeTo: to.UTC().Format(time.RFC3339Nano),
	}
}

func decodeHistory(events, signals []json.RawMessage) (ports.HistorySnapshot, error) {
	result := ports.HistorySnapshot{}
	for index, raw := range events {
		wire := &eventv1.CanonicalEvent{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, wire); err != nil {
			return result, fmt.Errorf("decode event history %d: %w", index, err)
		}
		event, err := contractmapper.EventToDomain(wire)
		if err != nil {
			return result, err
		}
		result.Events = append(result.Events, event)
	}
	for index, raw := range signals {
		observedAt := documentObservedAt(raw)
		wire := &signalv1.Signal{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, wire); err != nil {
			return result, fmt.Errorf("decode signal history %d: %w", index, err)
		}
		signal, err := contractmapper.SignalToDomain(wire)
		if err != nil {
			return result, err
		}
		result.Signals = append(result.Signals, ports.ObservedSignal{Signal: signal, ObservedAt: observedAt})
	}
	return result, nil
}

func documentObservedAt(raw json.RawMessage) time.Time {
	var envelope struct {
		Timestamp string `json:"@timestamp"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return time.Time{}
	}
	observed, _ := time.Parse(time.RFC3339Nano, envelope.Timestamp)
	return observed.UTC()
}

func filterTenantDocuments(raw []json.RawMessage, tenantID string) []json.RawMessage {
	result := make([]json.RawMessage, 0, len(raw))
	for _, document := range raw {
		var envelope struct {
			TenantID string `json:"tenant_id"`
		}
		if json.Unmarshal(document, &envelope) == nil && envelope.TenantID == tenantID {
			result = append(result, document)
		}
	}
	return result
}

func cloneStringMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
