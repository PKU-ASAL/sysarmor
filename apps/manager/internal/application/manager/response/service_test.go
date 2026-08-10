package response

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestApprovalCreatesPendingCommandOnlyAtThreshold(t *testing.T) {
	repository := &responseRepositoryStub{current: awaitingResponse(t)}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(200, 0).UTC()}, &responseIDStub{values: []string{"audit-a", "audit-b"}})

	first, err := service.Approve(context.Background(), responseAdminRequest(t, "admin-a"), ApprovalCommand{
		ResponseID: "response-a", AgentID: "agent-a", Approved: true, Role: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != domainresponse.StatusPendingApproval || audits.appends != 1 || repository.puts != 1 {
		t.Fatalf("first=%+v puts=%d audits=%d", first, repository.puts, audits.appends)
	}
	repository.current = first
	second, err := service.Approve(context.Background(), responseAdminRequest(t, "admin-b"), ApprovalCommand{
		ResponseID: "response-a", AgentID: "agent-a", Approved: true, Role: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != domainresponse.StatusPending || audits.appends != 2 || repository.puts != 2 {
		t.Fatalf("second=%+v puts=%d audits=%d", second, repository.puts, audits.appends)
	}
}

func TestApprovalReturnsNoResultWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	repository := &responseRepositoryStub{current: awaitingResponse(t)}
	service := NewService(&responseUnitOfWorkStub{
		tx: responseTransactionStub{responses: repository, audits: &responseAuditRepositoryStub{}}, commitErr: wantErr,
	}, responseClockStub{now: time.Unix(200, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})

	result, err := service.Approve(context.Background(), responseAdminRequest(t, "admin-a"), ApprovalCommand{
		ResponseID: "response-a", AgentID: "agent-a", Approved: true, Role: "admin",
	})
	if !errors.Is(err, wantErr) || !reflect.DeepEqual(result, domainresponse.Command{}) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func TestApprovalDoesNotRewriteIdenticalDecision(t *testing.T) {
	current, err := awaitingResponse(t).Decide(domainresponse.Approval{
		Actor: "admin-a", Role: "admin", Approved: true,
	}, time.Unix(150, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	repository := &responseRepositoryStub{current: current}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(200, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})

	result, err := service.Approve(context.Background(), responseAdminRequest(t, "admin-a"), ApprovalCommand{
		ResponseID: "response-a", AgentID: "agent-a", Approved: true, Role: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, current) || repository.puts != 0 || audits.appends != 0 {
		t.Fatalf("result=%+v puts=%d audits=%d", result, repository.puts, audits.appends)
	}
}

func TestApprovalDoesNotRewriteIdenticalFinalDecision(t *testing.T) {
	for _, approved := range []bool{true, false} {
		t.Run(map[bool]string{true: "approved", false: "rejected"}[approved], func(t *testing.T) {
			assertFinalApprovalReplay(t, approved)
		})
	}
}

func assertFinalApprovalReplay(t *testing.T, approved bool) {
	t.Helper()
	awaiting, err := domainresponse.NewCommand(domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", ApprovalRequired: true,
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	current, err := awaiting.Decide(domainresponse.Approval{
		Actor: "admin-a", Role: "admin", Approved: approved,
	}, time.Unix(150, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	repository := &responseRepositoryStub{current: current}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(200, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})

	result, err := service.Approve(context.Background(), responseAdminRequest(t, "admin-a"), ApprovalCommand{
		ResponseID: "response-a", AgentID: "agent-a", Approved: approved, Role: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, current) || repository.puts != 0 || audits.appends != 0 {
		t.Fatalf("result=%+v puts=%d audits=%d", result, repository.puts, audits.appends)
	}
}

func TestCreateUsesAuthenticatedTenantAndPersistsDenial(t *testing.T) {
	repository := &responseRepositoryStub{}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(300, 0).UTC()}, &responseIDStub{values: []string{"response-a", "audit-a"}})

	result, err := service.Create(context.Background(), responseOperatorRequest(t), CreateCommand{
		Value:  domainresponse.Command{AgentID: "agent-a", Action: "kill", Mode: "enforce"},
		Policy: domainresponse.Policy{AllowedActions: []string{"collect"}, AllowedModes: []string{"observe"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed || result.Command.TenantID != "tenant-a" || result.Command.Actor != "operator-a" ||
		result.Command.Status != domainresponse.StatusDenied || repository.creates != 1 || audits.appends != 1 {
		t.Fatalf("result=%+v creates=%d audits=%d", result, repository.creates, audits.appends)
	}
}

func TestAcknowledgeWritesCommandAndAuditAtomically(t *testing.T) {
	repository := &responseRepositoryStub{current: domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domainresponse.StatusPending,
	}}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(400, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})

	result, err := service.Acknowledge(context.Background(), AcknowledgeCommand{
		TenantID: "tenant-a", ResponseID: "response-a", AgentID: "agent-a", Accepted: true, Executed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Command.Status != domainresponse.StatusAcknowledged || result.Command.Ack == nil ||
		repository.puts != 1 || audits.appends != 1 {
		t.Fatalf("result=%+v puts=%d audits=%d", result, repository.puts, audits.appends)
	}
}

func TestAcknowledgeDoesNotRewriteIdenticalCompletedResult(t *testing.T) {
	ack := domainresponse.Acknowledgement{
		TenantID: "tenant-a", AgentID: "agent-a", Accepted: true, Executed: true, Message: "done",
	}
	completed, err := (domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domainresponse.StatusPending,
	}).Acknowledge(ack, time.Unix(300, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	repository := &responseRepositoryStub{current: completed.Command}
	audits := &responseAuditRepositoryStub{}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository, audits: audits}},
		responseClockStub{now: time.Unix(400, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})

	result, err := service.Acknowledge(context.Background(), AcknowledgeCommand{
		TenantID: "tenant-a", ResponseID: "response-a", AgentID: "agent-a",
		Accepted: true, Executed: true, Message: "done",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, completed) || repository.puts != 0 || audits.appends != 0 {
		t.Fatalf("result=%+v puts=%d audits=%d", result, repository.puts, audits.appends)
	}
}

func TestListUsesAuthenticatedTenant(t *testing.T) {
	repository := &responseRepositoryStub{listed: []domainresponse.Command{{ID: "response-a"}}}
	service := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{responses: repository}}, nil, nil)

	result, err := service.List(context.Background(), responseAdminRequest(t, "admin-a"), Query{AgentID: "agent-a", Pending: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || repository.listTenant != "tenant-a" || !repository.filter.Pending {
		t.Fatalf("result=%+v tenant=%q filter=%+v", result, repository.listTenant, repository.filter)
	}
}

type responseUnitOfWorkStub struct {
	tx        ports.ResponseTransaction
	commitErr error
}

func (stub *responseUnitOfWorkStub) Execute(ctx context.Context, fn func(context.Context, ports.ResponseTransaction) error) error {
	if err := fn(ctx, stub.tx); err != nil {
		return err
	}
	return stub.commitErr
}

type responseTransactionStub struct {
	responses ports.ResponseRepository
	audits    ports.ResponseAuditRepository
}

func (stub responseTransactionStub) Responses() ports.ResponseRepository   { return stub.responses }
func (stub responseTransactionStub) Audits() ports.ResponseAuditRepository { return stub.audits }

type responseRepositoryStub struct {
	current    domainresponse.Command
	listed     []domainresponse.Command
	listTenant tenant.ID
	filter     ports.ResponseFilter
	puts       int
	creates    int
}

func (stub *responseRepositoryStub) Get(context.Context, tenant.ID, string) (domainresponse.Command, error) {
	return stub.current, nil
}

func (stub *responseRepositoryStub) List(_ context.Context, tenantID tenant.ID, filter ports.ResponseFilter) ([]domainresponse.Command, error) {
	stub.listTenant, stub.filter = tenantID, filter
	return stub.listed, nil
}

func (stub *responseRepositoryStub) Create(_ context.Context, value domainresponse.Command) (domainresponse.Command, error) {
	stub.creates++
	stub.current = value
	return value, nil
}

func (stub *responseRepositoryStub) Put(_ context.Context, _, next domainresponse.Command) error {
	stub.puts++
	stub.current = next
	return nil
}

type responseAuditRepositoryStub struct{ appends int }

func (stub *responseAuditRepositoryStub) Append(context.Context, domainresponse.AuditRecord) error {
	stub.appends++
	return nil
}

type responseClockStub struct{ now time.Time }

func (stub responseClockStub) Now() time.Time { return stub.now }

type responseIDStub struct {
	values []string
	index  int
}

func (stub *responseIDStub) New() string {
	value := stub.values[stub.index]
	stub.index++
	return value
}

func awaitingResponse(t *testing.T) domainresponse.Command {
	t.Helper()
	value, err := domainresponse.NewCommand(domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "collect",
		ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"admin"},
	}, time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func responseAdminRequest(t *testing.T, subject string) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: subject, TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin),
	}}
}

func responseOperatorRequest(t *testing.T) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
	}}
}
