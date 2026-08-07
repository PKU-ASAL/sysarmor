package managerapi

import (
	"fmt"
	"net/http"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
)

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.searcher == nil {
		if s.localTelemetry {
			q := r.URL.Query()
			writeIncidentList(w, pageSlice(s.store.ListIncidentsForTenant(requestTenantID(r), parseLabelSelector(q["label"])), parseUint(q.Get("limit")), parseUint(q.Get("offset"))))
			return
		}
		http.Error(w, "incident report search is unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	labels := parseLabelSelector(q["label"])
	tenantID := q.Get("tenant_id")
	if tenantID == "" {
		http.Error(w, "tenant_id is required", http.StatusBadRequest)
		return
	}
	exact := incidentExactFilter(q.Get("incident_id"))
	if exact == nil {
		exact = map[string]string{}
	}
	exact["tenant_id"] = tenantID
	limit := parseUint(q.Get("limit"))
	offset := parseUint(q.Get("offset"))
	raw, err := s.searchTelemetry(r.Context(), platformopensearch.SearchRequest{
		Index:  platformopensearch.IncidentsReadAlias,
		Size:   searchLimit(limit),
		Offset: int(offset),
		Labels: labels,
		Exact:  exact,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("query incidents: %v", err), http.StatusBadGateway)
		return
	}
	raw = filterRawTelemetry(raw, labels, rawStringEquals("tenant_id", tenantID))
	if q.Get("incident_id") != "" {
		if len(raw) == 0 {
			http.Error(w, "incident report not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw[0])
		return
	}
	writeRawList(w, raw)
}

func incidentExactFilter(id string) map[string]string {
	if id == "" {
		return nil
	}
	return map[string]string{"id": id}
}
