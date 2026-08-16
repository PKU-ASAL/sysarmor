package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type TelemetryReader struct{ searcher Searcher }

func NewTelemetryReader(searcher Searcher) *TelemetryReader {
	return &TelemetryReader{searcher: searcher}
}

func (reader *TelemetryReader) Events(ctx context.Context, tenantID tenant.ID, filter ports.EventFilter) ([]domaintelemetry.Document, error) {
	exact := map[string]string{"tenant_id": tenantID.String()}
	if filter.Behavior != "" {
		exact["behavior"] = filter.Behavior
	}
	request := SearchRequest{Index: EventsReadAlias, Size: telemetryLimit(filter.Limit), Offset: max(filter.Offset, 0),
		Labels: cloneTelemetryLabels(filter.Labels), Exact: exact}
	return reader.search(ctx, tenantID, request, filter.Labels, func(document map[string]any) bool {
		return stringFieldMatches(document, "behavior", filter.Behavior)
	})
}

func (reader *TelemetryReader) Signals(ctx context.Context, tenantID tenant.ID, filter ports.SignalFilter) ([]domaintelemetry.Document, error) {
	exact := map[string]string{"tenant_id": tenantID.String()}
	if filter.Layer != "" {
		exact["where"] = "SIGNAL_WHERE_" + strings.ToUpper(filter.Layer)
	}
	if filter.Stage != nil {
		exact["stage"] = signalStageName(*filter.Stage)
	}
	request := SearchRequest{Index: SignalsReadAlias, Size: telemetryLimit(filter.Limit), Offset: max(filter.Offset, 0),
		Labels: cloneTelemetryLabels(filter.Labels), Exact: exact}
	return reader.search(ctx, tenantID, request, filter.Labels, func(document map[string]any) bool {
		return signalDocumentMatches(document, filter)
	})
}

func (reader *TelemetryReader) Incidents(ctx context.Context, tenantID tenant.ID, filter ports.IncidentFilter) ([]domaintelemetry.Document, error) {
	exact := map[string]string{"tenant_id": tenantID.String()}
	if filter.ID != "" {
		exact["id"] = filter.ID
	}
	request := SearchRequest{Index: IncidentsReadAlias, Size: telemetryLimit(filter.Limit), Offset: max(filter.Offset, 0),
		Labels: cloneTelemetryLabels(filter.Labels), Exact: exact}
	return reader.search(ctx, tenantID, request, filter.Labels, func(document map[string]any) bool {
		return stringFieldMatches(document, "id", filter.ID)
	})
}

func (reader *TelemetryReader) IncidentOverview(ctx context.Context, tenantID tenant.ID) (domaintelemetry.IncidentOverview, error) {
	documents, err := reader.Incidents(ctx, tenantID, ports.IncidentFilter{Limit: 1000})
	if err != nil {
		return domaintelemetry.IncidentOverview{}, err
	}
	result := domaintelemetry.IncidentOverview{}
	for _, document := range documents {
		var incident struct {
			Severity int `json:"severity"`
		}
		if err := json.Unmarshal(document, &incident); err != nil {
			return domaintelemetry.IncidentOverview{}, failure.New(failure.Internal, fmt.Sprintf("decode incident: %v", err))
		}
		addIncidentSeverity(&result, incident.Severity)
	}
	return result, nil
}

func addIncidentSeverity(result *domaintelemetry.IncidentOverview, severity int) {
	result.Open++
	switch {
	case severity >= 90:
		result.Critical++
	case severity >= 70:
		result.High++
	case severity >= 40:
		result.Medium++
	}
}

func (reader *TelemetryReader) search(ctx context.Context, tenantID tenant.ID, request SearchRequest, labels map[string]string, matches func(map[string]any) bool) ([]domaintelemetry.Document, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	if reader == nil || reader.searcher == nil {
		return nil, failure.New(failure.Internal, "telemetry searcher is required")
	}
	raw, err := reader.searcher.Search(ctx, request)
	if err != nil {
		return nil, failure.New(failure.RetryableDependency, fmt.Sprintf("search telemetry: %v", err))
	}
	result := make([]domaintelemetry.Document, 0, len(raw))
	for _, item := range raw {
		var document map[string]any
		if json.Unmarshal(item, &document) != nil || !telemetryDocumentMatches(document, tenantID, labels, matches) {
			continue
		}
		result = append(result, domaintelemetry.Document(item).Clone())
	}
	return result, nil
}

func telemetryDocumentMatches(document map[string]any, tenantID tenant.ID, labels map[string]string, matches func(map[string]any) bool) bool {
	if value, _ := document["tenant_id"].(string); value != tenantID.String() {
		return false
	}
	rawLabels, _ := document["labels"].(map[string]any)
	for key, want := range labels {
		if got, _ := rawLabels[key].(string); got != want {
			return false
		}
	}
	return matches == nil || matches(document)
}

func signalDocumentMatches(document map[string]any, filter ports.SignalFilter) bool {
	if filter.Layer != "" {
		where, _ := document["where"].(string)
		where = strings.ToLower(strings.TrimPrefix(where, "SIGNAL_WHERE_"))
		if where != strings.ToLower(filter.Layer) {
			return false
		}
	}
	if filter.Stage != nil {
		return stringFieldMatches(document, "stage", signalStageName(*filter.Stage))
	}
	return true
}

func signalStageName(stage domaintelemetry.SignalStage) string {
	switch stage {
	case domaintelemetry.SignalStageCandidate:
		return "SIGNAL_STAGE_CANDIDATE"
	case domaintelemetry.SignalStageConclusion:
		return "SIGNAL_STAGE_CONCLUSION"
	default:
		return "SIGNAL_STAGE_UNSPECIFIED"
	}
}

func stringFieldMatches(document map[string]any, field, want string) bool {
	if want == "" {
		return true
	}
	got, _ := document[field].(string)
	return got == want
}

func telemetryLimit(value int) int {
	if value <= 0 {
		return 1000
	}
	return value
}

func cloneTelemetryLabels(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
