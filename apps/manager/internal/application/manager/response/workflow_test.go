package response

import (
	"context"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestWorkflowDecideResolvesSignalAndPreparationBeforeCreate(t *testing.T) {
	repository := &responseRepositoryStub{}
	core := NewService(&responseUnitOfWorkStub{tx: responseTransactionStub{
		responses: repository, audits: &responseAuditRepositoryStub{},
	}}, responseClockStub{now: time.Unix(300, 0).UTC()}, &responseIDStub{values: []string{"audit-a"}})
	signals := &responseSignalResolverStub{command: domainresponse.Command{
		ID: "resp-signal-a", AgentID: "agent-a", Action: "collect",
	}}
	preparation := &responsePreparationResolverStub{value: Preparation{
		Policy: domainresponse.Policy{AllowedActions: []string{"collect"}, AllowedModes: []string{"observe"}},
	}}
	workflow := NewWorkflow(core, preparation, signals)
	request := responseOperatorRequest(t)

	result, err := workflow.Decide(context.Background(), request, DecisionCommand{
		SignalID: "signal-a", AgentID: "agent-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed || result.Command.ID != "resp-signal-a" || repository.creates != 1 ||
		signals.query.SignalID != "signal-a" || preparation.command.ID != "resp-signal-a" {
		t.Fatalf("result=%+v creates=%d signal=%+v prepared=%+v", result, repository.creates, signals.query, preparation.command)
	}
}

func TestWorkflowRejectsViewerBeforeCallingResolvers(t *testing.T) {
	preparation := &responsePreparationResolverStub{}
	signals := &responseSignalResolverStub{}
	workflow := NewWorkflow(&Service{}, preparation, signals)
	request := managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "viewer-a", TenantID: "tenant-a", Roles: tenant.NewRoleSet(tenant.RoleViewer),
	}}

	_, createErr := workflow.Create(context.Background(), request, domainresponse.Command{AgentID: "agent-a"})
	_, decideErr := workflow.Decide(context.Background(), request, DecisionCommand{SignalID: "signal-a", AgentID: "agent-a"})

	if failure.KindOf(createErr) != failure.PermissionDenied || failure.KindOf(decideErr) != failure.PermissionDenied {
		t.Fatalf("create kind=%v decide kind=%v", failure.KindOf(createErr), failure.KindOf(decideErr))
	}
	if preparation.calls != 0 || signals.calls != 0 {
		t.Fatalf("preparation calls=%d signal calls=%d", preparation.calls, signals.calls)
	}
}

type responseSignalResolverStub struct {
	command domainresponse.Command
	query   DecisionCommand
	calls   int
}

func (stub *responseSignalResolverStub) Resolve(_ context.Context, _ managerapp.RequestContext, query DecisionCommand) (domainresponse.Command, error) {
	stub.calls++
	stub.query = query
	return stub.command, nil
}

type responsePreparationResolverStub struct {
	value   Preparation
	command domainresponse.Command
	calls   int
}

func (stub *responsePreparationResolverStub) Resolve(_ context.Context, _ managerapp.RequestContext, command domainresponse.Command) (Preparation, error) {
	stub.calls++
	stub.command = command
	return stub.value, nil
}
