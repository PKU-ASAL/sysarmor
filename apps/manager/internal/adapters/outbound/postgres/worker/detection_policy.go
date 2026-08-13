package worker

import (
	"context"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type DetectionPolicies struct {
	policies ports.PolicyUnitOfWork
}

func NewDetectionPolicies(policies ports.PolicyUnitOfWork) *DetectionPolicies {
	return &DetectionPolicies{policies: policies}
}

func (reader *DetectionPolicies) Published(ctx context.Context, tenantID tenant.ID, policyID domainpolicy.ID, version domainpolicy.Version) (domaindetection.Policy, error) {
	var policy domainpolicy.Policy
	err := reader.policies.Execute(ctx, func(txCtx context.Context, tx ports.PolicyTransaction) error {
		var err error
		policy, err = tx.Policies().Published(txCtx, tenantID, policyID, version)
		return err
	})
	if err != nil {
		return domaindetection.Policy{}, err
	}
	return contractmapper.DetectionPolicyFromDocument(policy.Document)
}
