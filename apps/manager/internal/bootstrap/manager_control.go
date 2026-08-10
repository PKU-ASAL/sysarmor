package bootstrap

import (
	"context"
	"database/sql"
	"fmt"

	controlhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/control"
	controlpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/control"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

func NewManagerControlHTTP(db *sql.DB, resolve controlhttp.RequestContextResolver) (*controlhttp.Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("manager control database is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager control request context resolver is required")
	}
	uow := controlpostgres.NewUnitOfWork(db)
	management := controlapp.NewManagementService(uow, systemClock{}, uuidGenerator{})
	queries := controlapp.NewQueryService(uow)
	policies := policyPayloadResolver{query: policyapp.NewQueryService(policypostgres.NewUnitOfWork(db))}
	return controlhttp.NewHandler(controlhttp.Options{
		Management: management, Query: queries, Policies: policies, Resolve: resolve,
	}), nil
}

type policyQueries interface {
	GetPolicy(context.Context, managerapp.RequestContext, policyapp.GetPolicyQuery) (policyapp.GetPolicyResult, error)
}

type policyPayloadResolver struct{ query policyQueries }

func (resolver policyPayloadResolver) Resolve(ctx context.Context, request managerapp.RequestContext, id string, version uint64) ([]byte, string, uint64, error) {
	result, err := resolver.query.GetPolicy(ctx, request, policyapp.GetPolicyQuery{
		PolicyID: domainpolicy.ID(id), Version: domainpolicy.Version(version),
	})
	if err != nil {
		return nil, "", 0, err
	}
	return append([]byte(nil), result.Policy.DownlinkDocument...), result.Policy.ID.String(), uint64(result.Policy.Version), nil
}
