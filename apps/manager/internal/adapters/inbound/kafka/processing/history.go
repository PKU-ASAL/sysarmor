package processing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type OpenSearchHistory struct {
	searcher platformopensearch.Searcher
}

func (h *OpenSearchHistory) ReadDocuments(ctx context.Context, tenantID string, labels map[string]string, from, to time.Time) (ports.HistorySnapshot, error) {
	if h == nil || h.searcher == nil {
		return ports.HistorySnapshot{}, nil
	}
	request := platformopensearch.SearchRequest{Size: 10000, Labels: cloneStringMap(labels), Exact: map[string]string{"tenant_id": tenantID}, TimeField: "@timestamp", TimeFrom: from.UTC().Format(time.RFC3339Nano), TimeTo: to.UTC().Format(time.RFC3339Nano), Index: platformopensearch.EventsReadAlias}
	events, err := h.searcher.Search(ctx, request)
	if err != nil {
		return ports.HistorySnapshot{}, fmt.Errorf("read event history: %w", err)
	}
	request.Index = platformopensearch.SignalsReadAlias
	request.Exact["where"] = "SIGNAL_WHERE_ENDPOINT"
	signals, err := h.searcher.Search(ctx, request)
	if err != nil {
		return ports.HistorySnapshot{}, fmt.Errorf("read signal history: %w", err)
	}
	return ports.HistorySnapshot{Events: documentBytes(filterTenantDocuments(events, tenantID)), Signals: documentBytes(filterTenantDocuments(signals, tenantID))}, nil
}

func documentBytes(documents []json.RawMessage) [][]byte {
	result := make([][]byte, 0, len(documents))
	for _, document := range documents {
		result = append(result, append([]byte(nil), document...))
	}
	return result
}

func NewOpenSearchHistory(searcher platformopensearch.Searcher) *OpenSearchHistory {
	return &OpenSearchHistory{searcher: searcher}
}

func filterTenantDocuments(raw []json.RawMessage, tenantID string) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(raw))
	for _, document := range raw {
		var envelope struct {
			TenantID string `json:"tenant_id"`
		}
		if json.Unmarshal(document, &envelope) == nil && envelope.TenantID == tenantID {
			out = append(out, document)
		}
	}
	return out
}

func decodeEvents(raw [][]byte) ([]*eventv1.CanonicalEvent, error) {
	out := make([]*eventv1.CanonicalEvent, 0, len(raw))
	for _, document := range raw {
		event := &eventv1.CanonicalEvent{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(document, event); err != nil {
			return nil, fmt.Errorf("decode event history: %w", err)
		}
		out = append(out, event)
	}
	return out, nil
}

func decodeSignals(raw [][]byte) ([]*signalv1.Signal, error) {
	out := make([]*signalv1.Signal, 0, len(raw))
	for _, document := range raw {
		signal := &signalv1.Signal{}
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(document, signal); err != nil {
			return nil, fmt.Errorf("decode signal history: %w", err)
		}
		out = append(out, signal)
	}
	return out, nil
}

func mergeEvents(history, current []*eventv1.CanonicalEvent) []*eventv1.CanonicalEvent {
	byID := make(map[string]*eventv1.CanonicalEvent, len(history)+len(current))
	for _, event := range append(append([]*eventv1.CanonicalEvent{}, history...), current...) {
		if event != nil && event.GetId() != "" {
			byID[event.GetId()] = event
		}
	}
	out := make([]*eventv1.CanonicalEvent, 0, len(byID))
	for _, event := range byID {
		out = append(out, event)
	}
	return out
}

func mergeSignals(history, current []*signalv1.Signal) []*signalv1.Signal {
	byID := make(map[string]*signalv1.Signal, len(history)+len(current))
	for _, signal := range append(append([]*signalv1.Signal{}, history...), current...) {
		if signal != nil && SignalDocumentID(signal) != "" {
			byID[SignalDocumentID(signal)] = signal
		}
	}
	out := make([]*signalv1.Signal, 0, len(byID))
	for _, signal := range byID {
		out = append(out, signal)
	}
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	out := make(map[string]string, len(input)+1)
	for key, value := range input {
		out[key] = value
	}
	return out
}
