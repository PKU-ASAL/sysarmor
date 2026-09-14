package telemetry

import (
	"context"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type SearchQuery struct {
	Indexes   []domaintelemetry.Index
	Query     string
	Exact     map[string]string
	Limit     int
	Offset    int
	TimeField string
	TimeFrom  string
	TimeTo    string
	SortField string
	SortDesc  bool
}

type SearchService struct{ reader ports.TelemetrySearchReader }

func NewSearchService(reader ports.TelemetrySearchReader) *SearchService {
	return &SearchService{reader: reader}
}

func (service *SearchService) Search(ctx context.Context, request managerapp.RequestContext, query SearchQuery) ([]domaintelemetry.IndexedDocument, error) {
	if err := service.authorize(request, query.Indexes); err != nil {
		return nil, err
	}
	result := []domaintelemetry.IndexedDocument{}
	for _, index := range query.Indexes {
		documents, err := service.reader.Search(ctx, request.Actor.TenantID, searchFilter(query, index))
		if err != nil {
			return nil, err
		}
		result = append(result, documents...)
	}
	return result, nil
}

func (service *SearchService) authorize(request managerapp.RequestContext, indexes []domaintelemetry.Index) error {
	if request.Actor.TenantID.IsZero() {
		return failure.New(failure.InvalidArgument, "tenant is required")
	}
	if service == nil || service.reader == nil {
		return failure.New(failure.Internal, "telemetry search reader is required")
	}
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return err
	}
	for _, index := range indexes {
		if index != domaintelemetry.IndexEvents && index != domaintelemetry.IndexSignals {
			return failure.New(failure.InvalidArgument, "unsupported telemetry index")
		}
	}
	return nil
}

func searchFilter(query SearchQuery, index domaintelemetry.Index) ports.TelemetrySearchFilter {
	return ports.TelemetrySearchFilter{Index: index, Query: strings.TrimSpace(query.Query), Exact: cloneLabels(query.Exact),
		Limit: query.Limit, Offset: query.Offset, TimeField: strings.TrimSpace(query.TimeField),
		TimeFrom: strings.TrimSpace(query.TimeFrom), TimeTo: strings.TrimSpace(query.TimeTo),
		SortField: strings.TrimSpace(query.SortField), SortDesc: query.SortDesc}
}
