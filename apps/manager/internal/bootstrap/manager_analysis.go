package bootstrap

import (
	"context"
	"database/sql"
	"fmt"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	analysishttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/analysis"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	analysisapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/analysis"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

type effectivePolicyQuery interface {
	EffectivePolicy(context.Context, managerapp.RequestContext, policyapp.EffectivePolicyQuery) (policyapp.EffectivePolicyResult, error)
}

type managerAnalysisPolicy struct{ queries effectivePolicyQuery }

func (adapter managerAnalysisPolicy) Effective(ctx context.Context, request managerapp.RequestContext, target domainpolicy.Target) (detection.Policy, error) {
	result, err := adapter.queries.EffectivePolicy(ctx, request, policyapp.EffectivePolicyQuery{Target: target})
	if err != nil {
		return detection.Policy{}, err
	}
	return contractmapper.DetectionPolicyFromDocument(result.Policy.Document)
}

func NewManagerAnalysisHTTP(db *sql.DB, searcher platformopensearch.PageSearcher, resolve analysishttp.RequestContextResolver) (*analysishttp.Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("manager analysis database is required")
	}
	if searcher == nil {
		return nil, fmt.Errorf("manager analysis searcher is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager analysis request context resolver is required")
	}
	policies := policyapp.NewQueryService(policypostgres.NewUnitOfWork(db))
	rarity := identityapp.NewQueryService(identitypostgres.NewRepositories(db))
	signals := platformopensearch.NewAnalysisSignalReader(searcher)
	service := analysisapp.NewService(managerAnalysisPolicy{queries: policies}, rarity, signals)
	return analysishttp.NewHandler(analysishttp.Options{Service: service, Resolve: resolve}), nil
}
