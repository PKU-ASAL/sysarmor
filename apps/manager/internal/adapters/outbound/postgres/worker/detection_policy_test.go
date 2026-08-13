package worker

import (
	"context"
	"testing"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type policyUnitOfWorkStub struct {
	repository *policyRepositoryStub
}

func (stub *policyUnitOfWorkStub) Execute(ctx context.Context, run func(context.Context, ports.PolicyTransaction) error) error {
	return run(ctx, policyTransactionStub{repository: stub.repository})
}

type policyTransactionStub struct {
	ports.PolicyTransaction
	repository ports.PolicyRepository
}

func (stub policyTransactionStub) Policies() ports.PolicyRepository { return stub.repository }

type policyRepositoryStub struct {
	ports.PolicyRepository
	policyID domainpolicy.ID
	version  domainpolicy.Version
}

func (stub *policyRepositoryStub) Published(_ context.Context, tenantID tenant.ID, policyID domainpolicy.ID, version domainpolicy.Version) (domainpolicy.Policy, error) {
	stub.policyID, stub.version = policyID, version
	return domainpolicy.Policy{
		TenantID: tenantID, ID: policyID, Version: version, Published: true,
		Document: []byte(`{"cloud_rules":["web_shell_chain"],"converge":{"mode":"additive_threshold","cross_lineage":true,"additive_risk_threshold":120}}`),
	}, nil
}

func TestDetectionPoliciesReadsPublishedTelemetryPolicyVersion(t *testing.T) {
	repository := &policyRepositoryStub{}
	reader := NewDetectionPolicies(&policyUnitOfWorkStub{repository: repository})

	policy, err := reader.Published(t.Context(), tenant.ID("tenant-a"), "policy-old", 3)

	if err != nil || repository.policyID != "policy-old" || repository.version != 3 || len(policy.CloudRules) != 1 || policy.Converge == nil || policy.Converge.AdditiveRiskThreshold != 120 {
		t.Fatalf("policy=%+v requested=%s@%d err=%v", policy, repository.policyID, repository.version, err)
	}
}
