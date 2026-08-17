package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	analysisPageSize      = 500
	analysisDocumentLimit = 100_000
)

type AnalysisTelemetryReader struct{ searcher PageSearcher }

func NewAnalysisTelemetryReader(searcher PageSearcher) *AnalysisTelemetryReader {
	return &AnalysisTelemetryReader{searcher: searcher}
}

func (reader *AnalysisTelemetryReader) Events(ctx context.Context, tenantID tenant.ID, filter ports.AnalysisEventFilter) ([]domaintelemetry.Event, error) {
	request := analysisSearchRequest(EventsReadAlias, tenantID, filter.AgentID, filter.Labels, filter.From, filter.To)
	return readAnalysisValues(ctx, reader, tenantID, request, func(document domaintelemetry.Document) (domaintelemetry.Event, bool, error) {
		return decodeAnalysisEvent(document, tenantID, filter.Labels)
	})
}

func (reader *AnalysisTelemetryReader) Signals(ctx context.Context, tenantID tenant.ID, filter ports.AnalysisSignalFilter) ([]domaintelemetry.Signal, error) {
	request := analysisSearchRequest(SignalsReadAlias, tenantID, filter.AgentID, filter.Labels, filter.From, filter.To)
	if filter.Where != domaintelemetry.SignalWhereUnspecified {
		request.Exact["where"] = signalv1.SignalWhere(filter.Where).String()
	}
	return readAnalysisValues(ctx, reader, tenantID, request, func(document domaintelemetry.Document) (domaintelemetry.Signal, bool, error) {
		return decodeAnalysisSignal(document, tenantID, filter)
	})
}

func analysisSearchRequest(index string, tenantID tenant.ID, agentID string, labels map[string]string, from, to time.Time) SearchRequest {
	return SearchRequest{
		Index: index, Labels: cloneTelemetryLabels(labels),
		Exact:     map[string]string{"tenant_id": tenantID.String(), "agent_id": agentID},
		TimeField: "@timestamp", TimeFrom: from.UTC().Format(time.RFC3339Nano), TimeTo: to.UTC().Format(time.RFC3339Nano),
		SortField: "_id",
	}
}

func readAnalysisValues[T any](ctx context.Context, reader *AnalysisTelemetryReader, tenantID tenant.ID, request SearchRequest, decode func(domaintelemetry.Document) (T, bool, error)) ([]T, error) {
	if reader == nil || reader.searcher == nil {
		return nil, fmt.Errorf("analysis telemetry reader is required")
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("analysis tenant is required")
	}
	result := make([]T, 0)
	scanned := 0
	for pageNumber := 0; ; pageNumber++ {
		request.Size = min(analysisPageSize, analysisDocumentLimit-scanned)
		page, err := reader.searcher.SearchPage(ctx, request)
		if err != nil {
			return nil, failure.New(failure.RetryableDependency, fmt.Sprintf("search analysis telemetry page %d: %v", pageNumber, err))
		}
		hits := page.Hits[:min(len(page.Hits), request.Size)]
		scanned += len(hits)
		for index, hit := range hits {
			value, include, decodeErr := decode(domaintelemetry.Document(hit.Source))
			if decodeErr != nil {
				return nil, fmt.Errorf("decode analysis telemetry page %d hit %d: %w", pageNumber, index, decodeErr)
			}
			if include {
				result = append(result, value)
			}
		}
		if scanned >= analysisDocumentLimit || len(page.Hits) < request.Size {
			return result, nil
		}
		if len(page.Hits[len(page.Hits)-1].Sort) == 0 {
			return nil, fmt.Errorf("analysis telemetry page %d has no sort cursor", pageNumber)
		}
		request.SearchAfter = page.Hits[len(page.Hits)-1].Sort
	}
}

func decodeAnalysisEvent(document domaintelemetry.Document, tenantID tenant.ID, labels map[string]string) (domaintelemetry.Event, bool, error) {
	fields, include, err := analysisDocumentFields(document, tenantID, labels)
	if err != nil || !include {
		return domaintelemetry.Event{}, include, err
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return domaintelemetry.Event{}, false, err
	}
	var wire eventv1.CanonicalEvent
	if err := protojson.Unmarshal(raw, &wire); err != nil {
		return domaintelemetry.Event{}, false, err
	}
	value, err := contractmapper.EventToDomain(&wire)
	return value, true, err
}

func decodeAnalysisSignal(document domaintelemetry.Document, tenantID tenant.ID, filter ports.AnalysisSignalFilter) (domaintelemetry.Signal, bool, error) {
	fields, include, err := analysisDocumentFields(document, tenantID, filter.Labels)
	if err != nil || !include {
		return domaintelemetry.Signal{}, include, err
	}
	if filter.Where != domaintelemetry.SignalWhereUnspecified {
		var where string
		_ = json.Unmarshal(fields["where"], &where)
		if where != signalv1.SignalWhere(filter.Where).String() {
			return domaintelemetry.Signal{}, false, nil
		}
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return domaintelemetry.Signal{}, false, err
	}
	var wire signalv1.Signal
	if err := protojson.Unmarshal(raw, &wire); err != nil {
		return domaintelemetry.Signal{}, false, err
	}
	value, err := contractmapper.SignalToDomain(&wire)
	return value, true, err
}

func analysisDocumentFields(document domaintelemetry.Document, tenantID tenant.ID, labels map[string]string) (map[string]json.RawMessage, bool, error) {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(document, &fields); err != nil {
		return nil, false, err
	}
	if len(fields) == 0 {
		return nil, false, fmt.Errorf("analysis document must be a JSON object")
	}
	var rawTenant string
	if raw, ok := fields["tenant_id"]; !ok {
		return nil, false, fmt.Errorf("analysis tenant_id is required")
	} else if err := json.Unmarshal(raw, &rawTenant); err != nil || rawTenant == "" {
		return nil, false, fmt.Errorf("analysis tenant_id must be a string")
	} else if rawTenant != tenantID.String() {
		return nil, false, nil
	}
	labelsMatch, err := analysisLabelsMatch(fields["labels"], labels)
	if err != nil || !labelsMatch {
		return nil, false, err
	}
	delete(fields, "tenant_id")
	delete(fields, "@timestamp")
	return fields, true, nil
}

func analysisLabelsMatch(raw json.RawMessage, expected map[string]string) (bool, error) {
	if len(expected) == 0 {
		return true, nil
	}
	if len(raw) == 0 {
		return false, nil
	}
	labels := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &labels); err != nil {
		return false, fmt.Errorf("analysis labels must be an object")
	}
	for key, want := range expected {
		value, ok := labels[key]
		if !ok {
			return false, nil
		}
		var got string
		if err := json.Unmarshal(value, &got); err != nil {
			return false, fmt.Errorf("analysis label %q must be a string", key)
		}
		if got != want {
			return false, nil
		}
	}
	return true, nil
}
