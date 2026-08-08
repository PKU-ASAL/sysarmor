package policy

import (
	"context"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type QueryService struct{ uow ports.PolicyUnitOfWork }

func NewQueryService(uow ports.PolicyUnitOfWork) *QueryService { return &QueryService{uow: uow} }

type ListPoliciesQuery struct{ Filter domainpolicy.Filter }
type ListPoliciesResult struct{ Policies []domainpolicy.Policy }
type GetPolicyQuery struct {
	PolicyID domainpolicy.ID
	Version  domainpolicy.Version
}
type GetPolicyResult struct{ Policy domainpolicy.Policy }
type EffectivePolicyQuery struct{ Target domainpolicy.Target }
type EffectivePolicyResult struct{ Policy domainpolicy.Policy }

func (service *QueryService) GetPolicy(ctx context.Context, request managerapp.RequestContext, query GetPolicyQuery) (GetPolicyResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return GetPolicyResult{}, err
	}
	var result GetPolicyResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		value, err := tx.Policies().Get(txCtx, request.Actor.TenantID, query.PolicyID, query.Version)
		result.Policy = value
		return err
	})
	return result, err
}

func (service *QueryService) ListPolicies(ctx context.Context, request managerapp.RequestContext, query ListPoliciesQuery) (ListPoliciesResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ListPoliciesResult{}, err
	}
	var result ListPoliciesResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		values, err := tx.Policies().List(txCtx, request.Actor.TenantID, query.Filter)
		result.Policies = values
		return err
	})
	return result, err
}

func (service *QueryService) EffectivePolicy(ctx context.Context, request managerapp.RequestContext, query EffectivePolicyQuery) (EffectivePolicyResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return EffectivePolicyResult{}, err
	}
	var result EffectivePolicyResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		assignment, err := tx.Assignments().Effective(txCtx, request.Actor.TenantID, query.Target)
		if err != nil && failure.KindOf(err) != failure.NotFound {
			return fmt.Errorf("get effective policy assignment: %w", err)
		}
		if err == nil {
			value, publishedErr := tx.Policies().Published(txCtx, request.Actor.TenantID, assignment.PolicyID, assignment.PolicyVersion)
			if publishedErr == nil {
				result.Policy = value
				return nil
			}
			if failure.KindOf(publishedErr) != failure.NotFound {
				return publishedErr
			}
		}
		value, defaultErr := tx.Policies().Published(txCtx, request.Actor.TenantID, domainpolicy.DefaultPolicyID, 0)
		if failure.KindOf(defaultErr) == failure.NotFound {
			result.Policy = domainpolicy.ManagerDefault(request.Actor.TenantID)
			return nil
		}
		result.Policy = value
		return defaultErr
	})
	return result, err
}

func (service *QueryService) ListAssignments(ctx context.Context, request managerapp.RequestContext, filter domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	var result []domainpolicy.Assignment
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		var err error
		result, err = tx.Assignments().List(txCtx, request.Actor.TenantID, filter)
		return err
	})
	return result, err
}

func (service *QueryService) ListAudits(ctx context.Context, request managerapp.RequestContext, id domainpolicy.ID) ([]audit.Record, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	var result []audit.Record
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		var err error
		result, err = tx.Audits().List(txCtx, request.Actor.TenantID, id)
		return err
	})
	return result, err
}
