package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const analysisPageSize = 500

type AnalysisSignalReader struct{ searcher PageSearcher }

func NewAnalysisSignalReader(searcher PageSearcher) *AnalysisSignalReader {
	return &AnalysisSignalReader{searcher: searcher}
}

func (reader *AnalysisSignalReader) Signals(ctx context.Context, tenantID tenant.ID, filter ports.AnalysisSignalFilter) ([]domaintelemetry.Signal, error) {
	if reader == nil || reader.searcher == nil {
		return nil, fmt.Errorf("analysis telemetry reader is required")
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("analysis tenant is required")
	}
	request := SearchRequest{Index: SignalsReadAlias, Size: analysisPageSize, Labels: cloneTelemetryLabels(filter.Labels), Exact: map[string]string{"tenant_id": tenantID.String()}, SortField: "_id"}
	result := make([]domaintelemetry.Signal, 0)
	for pageNumber := 0; ; pageNumber++ {
		page, err := reader.searcher.SearchPage(ctx, request)
		if err != nil {
			return nil, failure.New(failure.RetryableDependency, fmt.Sprintf("search analysis signals page %d: %v", pageNumber, err))
		}
		for index, hit := range page.Hits {
			value, include, decodeErr := decodeAnalysisSignal(domaintelemetry.Document(hit.Source), tenantID, filter)
			if decodeErr != nil {
				return nil, fmt.Errorf("decode analysis signal page %d hit %d: %w", pageNumber, index, decodeErr)
			}
			if include {
				result = append(result, value)
			}
		}
		if len(page.Hits) < analysisPageSize {
			return result, nil
		}
		if len(page.Hits[len(page.Hits)-1].Sort) == 0 {
			return nil, fmt.Errorf("analysis signal page %d has no sort cursor", pageNumber)
		}
		request.SearchAfter = page.Hits[len(page.Hits)-1].Sort
	}
}

func decodeAnalysisSignal(document domaintelemetry.Document, tenantID tenant.ID, filter ports.AnalysisSignalFilter) (domaintelemetry.Signal, bool, error) {
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(document, &fields); err != nil {
		return domaintelemetry.Signal{}, false, err
	}
	if len(fields) == 0 {
		return domaintelemetry.Signal{}, false, fmt.Errorf("signal document must be a JSON object")
	}
	var rawTenant string
	if raw, ok := fields["tenant_id"]; !ok {
		return domaintelemetry.Signal{}, false, fmt.Errorf("signal tenant_id is required")
	} else if err := json.Unmarshal(raw, &rawTenant); err != nil || rawTenant == "" {
		return domaintelemetry.Signal{}, false, fmt.Errorf("signal tenant_id must be a string")
	} else if rawTenant != tenantID.String() {
		return domaintelemetry.Signal{}, false, nil
	}
	if filter.Layer != "" {
		var where string
		if raw, ok := fields["where"]; ok {
			_ = json.Unmarshal(raw, &where)
		}
		if strings.ToLower(strings.TrimPrefix(where, "SIGNAL_WHERE_")) != strings.ToLower(filter.Layer) {
			return domaintelemetry.Signal{}, false, nil
		}
	}
	labelsMatch, err := analysisLabelsMatch(fields["labels"], filter.Labels)
	if err != nil || !labelsMatch {
		return domaintelemetry.Signal{}, false, err
	}
	delete(fields, "tenant_id")
	delete(fields, "@timestamp")
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

func analysisLabelsMatch(raw json.RawMessage, expected map[string]string) (bool, error) {
	if len(expected) == 0 {
		return true, nil
	}
	if len(raw) == 0 {
		return false, nil
	}
	labels := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &labels); err != nil {
		return false, fmt.Errorf("signal labels must be an object")
	}
	for key, want := range expected {
		value, ok := labels[key]
		if !ok {
			return false, nil
		}
		var got string
		if err := json.Unmarshal(value, &got); err != nil {
			return false, fmt.Errorf("signal label %q must be a string", key)
		}
		if got != want {
			return false, nil
		}
	}
	return true, nil
}
