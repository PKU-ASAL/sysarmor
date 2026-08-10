package opensearch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func (reader *TelemetryReader) Search(ctx context.Context, tenantID tenant.ID, filter ports.TelemetrySearchFilter) ([]domaintelemetry.IndexedDocument, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	if reader == nil || reader.searcher == nil {
		return nil, failure.New(failure.Internal, "telemetry searcher is required")
	}
	exact := searchExactFields(filter.Exact)
	exact["tenant_id"] = tenantID.String()
	raw, err := reader.searcher.Search(ctx, SearchRequest{Index: searchIndex(filter.Index), Size: filter.Limit,
		Offset: max(filter.Offset, 0), Query: filter.Query, Exact: exact, TimeField: filter.TimeField,
		TimeFrom: filter.TimeFrom, TimeTo: filter.TimeTo, SortField: filter.SortField, SortDesc: filter.SortDesc})
	if err != nil {
		return nil, failure.New(failure.RetryableDependency, fmt.Sprintf("search telemetry: %v", err))
	}
	result := make([]domaintelemetry.IndexedDocument, 0, len(raw))
	for _, item := range raw {
		if documentTenant(item) != tenantID.String() {
			continue
		}
		result = append(result, domaintelemetry.IndexedDocument{Index: filter.Index,
			Document: domaintelemetry.Document(item).Clone()})
	}
	return result, nil
}

func searchIndex(index domaintelemetry.Index) string {
	if index == domaintelemetry.IndexSignals {
		return SignalsReadAlias
	}
	return EventsReadAlias
}

func searchExactFields(values map[string]string) map[string]string {
	result := make(map[string]string, len(values)+1)
	for field, value := range values {
		if field != "@timestamp" && field != "tenant_id" {
			field += ".keyword"
		}
		result[field] = value
	}
	return result
}

func documentTenant(raw []byte) string {
	var document struct {
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return ""
	}
	return document.TenantID
}
