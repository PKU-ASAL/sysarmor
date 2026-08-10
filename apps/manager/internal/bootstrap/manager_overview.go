package bootstrap

import (
	"fmt"

	overviewhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/overview"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	overviewapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/overview"
)

type ManagerStorageStatus = overviewapp.StorageStatus

func NewManagerOverviewHTTP(identity overviewapp.IdentityQuery, searcher platformopensearch.Searcher,
	status ManagerStorageStatus, resolve overviewhttp.RequestContextResolver) (*overviewhttp.Handler, error) {
	if identity == nil {
		return nil, fmt.Errorf("manager overview identity query is required")
	}
	if searcher == nil {
		return nil, fmt.Errorf("manager overview telemetry searcher is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager overview resolver is required")
	}
	service := overviewapp.NewService(identity, platformopensearch.NewTelemetryReader(searcher), status)
	return overviewhttp.NewHandler(overviewhttp.Options{Service: service, Resolve: resolve}), nil
}
