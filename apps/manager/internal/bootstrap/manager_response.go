package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	responsehttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/response"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	responsepostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/response"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
)

func NewManagerResponseHTTP(db *sql.DB, searcher platformopensearch.Searcher, resolve responsehttp.RequestContextResolver) (*responsehttp.Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("manager response database is required")
	}
	if searcher == nil {
		return nil, fmt.Errorf("manager response searcher is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager response request context resolver is required")
	}
	service := responseapp.NewService(responsepostgres.NewUnitOfWork(db), systemClock{}, uuidGenerator{})
	preparation := responsePreparationResolver{
		policies: policyapp.NewQueryService(policypostgres.NewUnitOfWork(db)),
		identity: identityapp.NewQueryService(identitypostgres.NewRepositories(db)),
	}
	workflow := responseapp.NewWorkflow(service, preparation, platformopensearch.NewResponseSignalResolver(searcher))
	return responsehttp.NewHandler(responsehttp.Options{Service: workflow, Resolve: resolve}), nil
}

type responsePolicyQueries interface {
	EffectivePolicy(context.Context, managerapp.RequestContext, policyapp.EffectivePolicyQuery) (policyapp.EffectivePolicyResult, error)
}

type responseIdentityQueries interface {
	GetHealth(context.Context, managerapp.RequestContext, domainidentity.AgentID) (domainidentity.Health, error)
}

type responsePreparationResolver struct {
	policies responsePolicyQueries
	identity responseIdentityQueries
}

func (resolver responsePreparationResolver) Resolve(ctx context.Context, request managerapp.RequestContext, command domainresponse.Command) (responseapp.Preparation, error) {
	result := responseapp.Preparation{}
	health, err := resolver.identity.GetHealth(ctx, request, domainidentity.AgentID(command.AgentID))
	if err != nil && failure.KindOf(err) != failure.NotFound {
		return responseapp.Preparation{}, err
	}
	if err == nil {
		result.Runtime = domainresponse.Scope{Type: health.Scope.Type, Selector: health.Scope.Selector}
		result.RuntimeKnown = true
	}
	targetScope := command.Scope
	if targetScope.Type == "" && targetScope.Selector == "" && result.RuntimeKnown {
		targetScope = result.Runtime
	}
	policyResult, err := resolver.policies.EffectivePolicy(ctx, request, policyapp.EffectivePolicyQuery{Target: domainpolicy.Target{
		AgentID: command.AgentID, ScopeType: targetScope.Type, ScopeSelector: targetScope.Selector,
	}})
	if err != nil {
		return responseapp.Preparation{}, err
	}
	policy, err := responsePolicy(policyResult.Policy.Document)
	if err != nil {
		return responseapp.Preparation{}, err
	}
	result.Policy, result.PolicyID = policy, policyResult.Policy.ID.String()
	result.PolicyVersion = uint64(policyResult.Policy.Version)
	return result, nil
}

func responsePolicy(document []byte) (domainresponse.Policy, error) {
	var envelope struct {
		Response struct {
			AllowedActions    []string `json:"allowed_actions"`
			AllowedModes      []string `json:"allowed_modes"`
			ApprovalRequired  bool     `json:"approval_required"`
			ApprovalThreshold uint32   `json:"approval_threshold"`
			ApprovalRoles     []string `json:"approval_roles"`
			AllowDestructive  bool     `json:"allow_destructive"`
		} `json:"response_policy"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		return domainresponse.Policy{}, fmt.Errorf("decode response policy: %w", err)
	}
	value := domainresponse.Policy{
		AllowedActions: envelope.Response.AllowedActions, AllowedModes: envelope.Response.AllowedModes,
		ApprovalRequired: envelope.Response.ApprovalRequired, ApprovalThreshold: envelope.Response.ApprovalThreshold,
		ApprovalRoles: envelope.Response.ApprovalRoles, AllowDestructive: envelope.Response.AllowDestructive,
	}
	if len(value.AllowedActions) == 0 && len(value.AllowedModes) == 0 {
		value.AllowedActions, value.AllowedModes = []string{"collect", "noop"}, []string{"observe"}
	}
	return value, nil
}
