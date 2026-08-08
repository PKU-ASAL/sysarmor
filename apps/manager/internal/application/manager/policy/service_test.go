package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	policyports "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestPublishPolicyCommitsPolicyAndAuditTogether(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: tenantID, ID: "policy-a", Version: 2})
	service := NewPublishService(uow, fixedClock{}, &sequenceIDs{"audit-a"})

	result, err := service.Execute(context.Background(), requestContext, PublishPolicyCommand{PolicyID: "policy-a", Version: 2, Published: true, Reason: "approved"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Policy.Published || len(uow.committed.policies) != 1 || len(uow.committed.audits) != 1 {
		t.Fatalf("committed state = %+v", uow.committed)
	}
	if uow.committed.audits[0].ID != "audit-a" || uow.committed.audits[0].Reason != "approved" {
		t.Fatalf("audit = %+v", uow.committed.audits[0])
	}
}

func TestPublishPolicyRollsBackWhenAuditFails(t *testing.T) {
	_, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{TenantID: requestContext.Actor.TenantID, ID: "policy-a", Version: 2})
	uow.failAudit = errors.New("audit unavailable")
	service := NewPublishService(uow, fixedClock{}, &sequenceIDs{"audit-a"})

	_, err := service.Execute(context.Background(), requestContext, PublishPolicyCommand{PolicyID: "policy-a", Version: 2})
	if err == nil {
		t.Fatal("Execute() succeeded with failed audit")
	}
	if len(uow.committed.policies) != 0 || len(uow.committed.audits) != 0 {
		t.Fatalf("partial state committed: %+v", uow.committed)
	}
}

func TestAssignPolicyCommitsAssignmentAuditAndControlTogether(t *testing.T) {
	tenantID, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{
		TenantID: tenantID, ID: "policy-a", Version: 3, Published: true, Document: []byte(`{"policy_id":"policy-a"}`),
	})
	service := NewAssignService(uow, fixedClock{}, &sequenceIDs{"assignment-a", "audit-a"})

	result, err := service.Execute(context.Background(), requestContext, AssignPolicyCommand{
		PolicyID: "policy-a", Version: 3, Target: domainpolicy.Target{AgentID: "agent-a"},
		Downlink: true, CommandID: "command-a", Reason: "rollout",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Control == nil || len(uow.committed.assignments) != 1 || len(uow.committed.audits) != 1 || len(uow.committed.controls) != 1 {
		t.Fatalf("committed state = %+v", uow.committed)
	}
	if result.Assignment.ID != "assignment-a" || result.Control.ID != "command-a" {
		t.Fatalf("result = %+v", result)
	}
}

func TestAssignPolicyRollsBackWhenControlFails(t *testing.T) {
	_, requestContext := policyRequestContext(t)
	uow := newFakePolicyUnitOfWork(domainpolicy.Policy{
		TenantID: requestContext.Actor.TenantID, ID: "policy-a", Version: 3, Published: true,
	})
	uow.failControl = errors.New("control unavailable")
	service := NewAssignService(uow, fixedClock{}, &sequenceIDs{"assignment-a", "audit-a"})

	_, err := service.Execute(context.Background(), requestContext, AssignPolicyCommand{
		PolicyID: "policy-a", Version: 3, Target: domainpolicy.Target{AgentID: "agent-a"}, Downlink: true, CommandID: "command-a",
	})
	if err == nil {
		t.Fatal("Execute() succeeded with failed control write")
	}
	if len(uow.committed.assignments) != 0 || len(uow.committed.audits) != 0 || len(uow.committed.controls) != 0 {
		t.Fatalf("partial state committed: %+v", uow.committed)
	}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 8, 8, 5, 6, 7, 0, time.UTC) }

type sequenceIDs []string

func (ids *sequenceIDs) New() string {
	value := (*ids)[0]
	*ids = (*ids)[1:]
	return value
}

func policyRequestContext(t *testing.T) (tenant.ID, managerapp.RequestContext) {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return tenantID, managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
	}}
}

type fakePolicyState struct {
	seed        domainpolicy.Policy
	policies    []domainpolicy.Policy
	assignments []domainpolicy.Assignment
	controls    []policyports.PolicyControlCommand
	audits      []audit.Record
}

type fakePolicyUnitOfWork struct {
	committed   fakePolicyState
	failAudit   error
	failControl error
}

func newFakePolicyUnitOfWork(seed domainpolicy.Policy) *fakePolicyUnitOfWork {
	return &fakePolicyUnitOfWork{committed: fakePolicyState{seed: seed}}
}

func (uow *fakePolicyUnitOfWork) Execute(ctx context.Context, fn func(context.Context, policyports.PolicyTransaction) error) error {
	staged := uow.committed
	tx := &fakePolicyTransaction{state: &staged, failAudit: uow.failAudit, failControl: uow.failControl}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	uow.committed = staged
	return nil
}

type fakePolicyTransaction struct {
	state       *fakePolicyState
	failAudit   error
	failControl error
}

func (tx *fakePolicyTransaction) Policies() policyports.PolicyRepository {
	return fakePolicies{tx.state}
}
func (tx *fakePolicyTransaction) Assignments() policyports.AssignmentRepository {
	return fakeAssignments{tx.state}
}
func (tx *fakePolicyTransaction) Controls() policyports.PolicyControlRepository {
	return fakeControls{state: tx.state, err: tx.failControl}
}
func (tx *fakePolicyTransaction) Audits() policyports.AuditRepository {
	return fakeAudits{state: tx.state, err: tx.failAudit}
}

type fakePolicies struct{ state *fakePolicyState }

func (repo fakePolicies) Get(context.Context, tenant.ID, domainpolicy.ID, domainpolicy.Version) (domainpolicy.Policy, error) {
	return repo.state.seed, nil
}
func (repo fakePolicies) Current(context.Context, tenant.ID, domainpolicy.ID) (domainpolicy.Policy, error) {
	return repo.state.seed, nil
}
func (repo fakePolicies) Put(_ context.Context, value domainpolicy.Policy) error {
	repo.state.policies = append(repo.state.policies, value)
	return nil
}

type fakeAssignments struct{ state *fakePolicyState }

func (repo fakeAssignments) Put(_ context.Context, value domainpolicy.Assignment) error {
	repo.state.assignments = append(repo.state.assignments, value)
	return nil
}

type fakeControls struct {
	state *fakePolicyState
	err   error
}

func (repo fakeControls) Put(_ context.Context, value policyports.PolicyControlCommand) error {
	if repo.err != nil {
		return repo.err
	}
	repo.state.controls = append(repo.state.controls, value)
	return nil
}

type fakeAudits struct {
	state *fakePolicyState
	err   error
}

func (repo fakeAudits) Append(_ context.Context, _ tenant.ID, value audit.Record) error {
	if repo.err != nil {
		return repo.err
	}
	repo.state.audits = append(repo.state.audits, value)
	return nil
}
