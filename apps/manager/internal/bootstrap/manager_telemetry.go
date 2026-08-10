package bootstrap

import (
	"fmt"

	searchhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/search"
	telemetryhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/telemetry"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	telemetryapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/telemetry"
)

func NewManagerTelemetryHTTP(searcher platformopensearch.Searcher, resolve telemetryhttp.RequestContextResolver) (*telemetryhttp.Handler, error) {
	if searcher == nil {
		return nil, fmt.Errorf("manager telemetry searcher is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager telemetry request context resolver is required")
	}
	service := telemetryapp.NewQueryService(platformopensearch.NewTelemetryReader(searcher))
	return telemetryhttp.NewHandler(telemetryhttp.Options{Service: service, Resolve: resolve}), nil
}

func NewManagerSearchHTTP(searcher platformopensearch.Searcher, resolve searchhttp.RequestContextResolver) (*searchhttp.Handler, error) {
	if searcher == nil {
		return nil, fmt.Errorf("manager search searcher is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager search request context resolver is required")
	}
	service := telemetryapp.NewSearchService(platformopensearch.NewTelemetryReader(searcher))
	return searchhttp.NewHandler(searchhttp.Options{Service: service, Resolve: resolve}), nil
}
