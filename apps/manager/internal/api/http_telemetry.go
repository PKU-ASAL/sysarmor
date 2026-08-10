package managerapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := requestTenantID(r)
	labels := parseLabelSelector(q["label"])
	limit := parseUint(q.Get("limit"))
	offset := parseUint(q.Get("offset"))
	if s.searcher != nil {
		raw, err := s.searchTelemetry(r.Context(), platformopensearch.SearchRequest{
			Index:  platformopensearch.EventsReadAlias,
			Size:   searchLimit(limit),
			Offset: int(offset),
			Labels: labels,
			Exact:  withTenantExact(stringExactFilter("behavior", q.Get("behavior")), tenantID),
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("query events: %v", err), http.StatusBadGateway)
			return
		}
		raw = filterRawTelemetry(raw, labels, rawAll(rawStringEquals("tenant_id", tenantID), rawStringEquals("behavior", q.Get("behavior"))))
		writeRawList(w, raw)
		return
	}
	writeEventList(w, pageSlice(s.store.ListEventsForTenant(tenantID, labels, q.Get("behavior")), limit, offset))
}

func (s *Server) signals(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tenantID := requestTenantID(r)
	labels := parseLabelSelector(q["label"])
	limit := parseUint(q.Get("limit"))
	offset := parseUint(q.Get("offset"))
	if s.searcher != nil {
		raw, err := s.searchTelemetry(r.Context(), platformopensearch.SearchRequest{
			Index:  platformopensearch.SignalsReadAlias,
			Size:   searchLimit(limit),
			Offset: int(offset),
			Labels: labels,
			Exact:  withTenantExact(signalExactFilter(q.Get("layer")), tenantID),
			Bool:   boolFilter("terminal", q.Get("terminal")),
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("query signals: %v", err), http.StatusBadGateway)
			return
		}
		raw = filterRawTelemetry(raw, labels, rawAll(rawStringEquals("tenant_id", tenantID), rawSignalMatches(q.Get("layer"), q.Get("terminal"))))
		writeRawList(w, raw)
		return
	}
	signals := s.store.ListSignalsForTenant(tenantID, labels, q.Get("layer"), q.Get("terminal") == "true")
	writeSignalList(w, pageSlice(signals, limit, offset))
}

func withTenantExact(exact map[string]string, tenantID string) map[string]string {
	if exact == nil {
		exact = map[string]string{}
	}
	exact["tenant_id"] = tenantID
	return exact
}

func rawAll(filters ...func(map[string]any) bool) func(map[string]any) bool {
	return func(doc map[string]any) bool {
		for _, filter := range filters {
			if filter != nil && !filter(doc) {
				return false
			}
		}
		return true
	}
}

func (s *Server) searchTelemetry(ctx context.Context, req platformopensearch.SearchRequest) ([]json.RawMessage, error) {
	if s.searcher == nil {
		return nil, nil
	}
	return s.searcher.Search(ctx, req)
}

func filterRawTelemetry(raw []json.RawMessage, labels store.LabelSelector, extra func(map[string]any) bool) []json.RawMessage {
	if len(labels) == 0 && extra == nil {
		return raw
	}
	out := make([]json.RawMessage, 0, len(raw))
	for _, item := range raw {
		var doc map[string]any
		if err := json.Unmarshal(item, &doc); err != nil {
			continue
		}
		if !rawLabelsMatch(doc, labels) {
			continue
		}
		if extra != nil && !extra(doc) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func rawLabelsMatch(doc map[string]any, labels store.LabelSelector) bool {
	if len(labels) == 0 {
		return true
	}
	raw, ok := doc["labels"].(map[string]any)
	if !ok {
		return false
	}
	for key, want := range labels {
		if got, _ := raw[key].(string); got != want {
			return false
		}
	}
	return true
}

func rawStringEquals(field, want string) func(map[string]any) bool {
	if strings.TrimSpace(want) == "" {
		return nil
	}
	return func(doc map[string]any) bool {
		got, _ := doc[field].(string)
		return got == want
	}
}

func rawSignalMatches(layer, terminal string) func(map[string]any) bool {
	layer = strings.TrimSpace(layer)
	terminal = strings.TrimSpace(terminal)
	if layer == "" && terminal == "" {
		return nil
	}
	return func(doc map[string]any) bool {
		if layer != "" && !rawSignalLayerMatches(doc["where"], layer) {
			return false
		}
		if terminal != "" {
			want := terminal == "true"
			got, ok := doc["terminal"].(bool)
			if !ok || got != want {
				return false
			}
		}
		return true
	}
}

func rawSignalLayerMatches(value any, layer string) bool {
	got, _ := value.(string)
	got = strings.ToLower(strings.TrimPrefix(got, "SIGNAL_WHERE_"))
	return got == strings.ToLower(layer)
}

func searchLimit(limit uint64) int {
	if limit == 0 {
		return 1000
	}
	return int(limit)
}

func stringExactFilter(field, value string) map[string]string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return map[string]string{field: value}
}

func signalExactFilter(layer string) map[string]string {
	layer = strings.TrimSpace(layer)
	if layer == "" {
		return nil
	}
	return map[string]string{"where": "SIGNAL_WHERE_" + strings.ToUpper(layer)}
}

func boolFilter(field, value string) map[string]bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return map[string]bool{field: value == "true"}
}
