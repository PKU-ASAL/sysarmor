package control

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestAcknowledgeCommandReturnsNoResultWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	commands := &commandRepositoryStub{current: domaincontrol.Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domaincontrol.CommandSent,
	}}
	audits := &controlAuditRepositoryStub{}
	service := NewResultService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{commands: commands, audits: audits}, commitErr: wantErr,
	}, clockStub{now: time.Unix(200, 0).UTC()}, &idGeneratorStub{values: []string{"audit-a"}})

	result, err := service.Acknowledge(context.Background(), AcknowledgeCommand{
		TenantID: "tenant-a", AgentID: "agent-a", CommandID: "command-a",
		Status: domaincontrol.CommandApplied, Message: "applied",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("acknowledge error = %v", err)
	}
	if !reflect.DeepEqual(result, domaincontrol.Command{}) {
		t.Fatalf("result escaped failed transaction = %+v", result)
	}
	if commands.puts != 1 || audits.appends != 1 || audits.last.ID != "audit-a" {
		t.Fatalf("writes command=%d audit=%d", commands.puts, audits.appends)
	}
}

func TestCompleteEvidenceWritesResultAndAuditAtomically(t *testing.T) {
	evidence := &evidenceRepositoryStub{current: domaincontrol.EvidencePullback{
		ID: "evidence-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domaincontrol.EvidencePending,
	}}
	audits := &controlAuditRepositoryStub{}
	service := NewResultService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{evidence: evidence, audits: audits},
	}, clockStub{now: time.Unix(300, 0).UTC()}, &idGeneratorStub{values: []string{"audit-a"}})

	result, err := service.CompleteEvidence(context.Background(), CompleteEvidenceCommand{
		TenantID: "tenant-a", AgentID: "agent-a", RequestID: "evidence-a", OK: true, Message: "collected",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domaincontrol.EvidenceCompleted || evidence.puts != 1 || audits.appends != 1 {
		t.Fatalf("result=%+v evidence writes=%d audit writes=%d", result, evidence.puts, audits.appends)
	}
}

func TestMarkSentWritesCommandAndAuditAtomically(t *testing.T) {
	commands := &commandRepositoryStub{current: domaincontrol.Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domaincontrol.CommandPending,
	}}
	audits := &controlAuditRepositoryStub{}
	service := NewDeliveryService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{commands: commands, audits: audits},
	}, clockStub{now: time.Unix(350, 0).UTC()}, &idGeneratorStub{values: []string{"audit-a"}})

	err := service.MarkSent(context.Background(), "tenant-a", "agent-a", "command-a")
	if err != nil {
		t.Fatal(err)
	}
	if commands.puts != 1 || commands.next.Status != domaincontrol.CommandSent || commands.next.AttemptCount != 1 {
		t.Fatalf("writes=%d next=%+v", commands.puts, commands.next)
	}
	if audits.appends != 1 || audits.last.Action != "send" || audits.last.Status != string(domaincontrol.CommandSent) {
		t.Fatalf("audit=%+v appends=%d", audits.last, audits.appends)
	}
}

func TestCreateCommandUsesActorTenantAndWritesAudit(t *testing.T) {
	commands := &commandRepositoryStub{}
	audits := &controlAuditRepositoryStub{}
	service := NewManagementService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{commands: commands, audits: audits},
	}, clockStub{now: time.Unix(400, 0).UTC()}, &idGeneratorStub{values: []string{"command-a", "audit-a"}})

	result, err := service.CreateCommand(context.Background(), adminControlRequest(t), CreateCommand{
		AgentID: "agent-a", Type: domaincontrol.CommandTypeContentUpdate,
		Payload: []byte(`{"kind":"iocpack"}`), Reason: "refresh",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "command-a" || result.TenantID != "tenant-a" || result.Actor != "operator-a" ||
		commands.creates != 1 || audits.appends != 1 {
		t.Fatalf("result=%+v creates=%d audits=%d", result, commands.creates, audits.appends)
	}
}

func TestCreateCommandRequiresAdmin(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	service := NewManagementService(nil, nil, nil)
	_, err := service.CreateCommand(context.Background(), managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
	}}, CreateCommand{AgentID: "agent-a", Type: domaincontrol.CommandTypeContentUpdate, Payload: []byte(`{}`)})
	if failure.KindOf(err) != failure.PermissionDenied {
		t.Fatalf("kind = %v error=%v", failure.KindOf(err), err)
	}
}

func TestControlActionReturnsNoResultWhenCommitFails(t *testing.T) {
	wantErr := errors.New("commit failed")
	commands := &commandRepositoryStub{current: domaincontrol.Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: domaincontrol.CommandSent,
	}}
	service := NewManagementService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{commands: commands, audits: &controlAuditRepositoryStub{}}, commitErr: wantErr,
	}, clockStub{now: time.Unix(500, 0).UTC()}, &idGeneratorStub{values: []string{"audit-a"}})

	result, err := service.Act(context.Background(), adminControlRequest(t), ActionCommand{
		CommandID: "command-a", AgentID: "agent-a", Action: ActionCancel, Reason: "stop",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("action error = %v", err)
	}
	if !reflect.DeepEqual(result, domaincontrol.Command{}) {
		t.Fatalf("result escaped failed transaction = %+v", result)
	}
}

func TestCreateEvidenceUsesActorTenant(t *testing.T) {
	evidence := &evidenceRepositoryStub{}
	service := NewManagementService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{evidence: evidence, audits: &controlAuditRepositoryStub{}},
	}, clockStub{now: time.Unix(600, 0).UTC()}, &idGeneratorStub{values: []string{"evidence-a", "audit-a"}})

	result, err := service.CreateEvidence(context.Background(), adminControlRequest(t), CreateEvidenceCommand{
		AgentID: "agent-a", IncidentID: "incident-a", Labels: map[string]string{"process": "sshd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != "evidence-a" || result.TenantID != "tenant-a" || evidence.creates != 1 {
		t.Fatalf("result=%+v creates=%d", result, evidence.creates)
	}
}

func TestQueryUsesAuthenticatedTenant(t *testing.T) {
	commands := &commandRepositoryStub{listed: []domaincontrol.Command{{ID: "command-a"}}}
	evidence := &evidenceRepositoryStub{listed: []domaincontrol.EvidencePullback{{ID: "evidence-a"}}}
	service := NewQueryService(&controlUnitOfWorkStub{
		tx: controlTransactionStub{commands: commands, evidence: evidence},
	})
	request := adminControlRequest(t)

	gotCommands, err := service.Commands(context.Background(), request, CommandQuery{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	gotEvidence, err := service.Evidence(context.Background(), request, EvidenceQuery{AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(gotCommands) != 1 || len(gotEvidence) != 1 ||
		commands.listTenant != request.Actor.TenantID || evidence.listTenant != request.Actor.TenantID {
		t.Fatalf("commands=%+v evidence=%+v tenants=%q/%q", gotCommands, gotEvidence, commands.listTenant, evidence.listTenant)
	}
}

type controlUnitOfWorkStub struct {
	tx        ports.ControlTransaction
	commitErr error
}

func (stub *controlUnitOfWorkStub) Execute(ctx context.Context, fn func(context.Context, ports.ControlTransaction) error) error {
	if err := fn(ctx, stub.tx); err != nil {
		return err
	}
	return stub.commitErr
}

type controlTransactionStub struct {
	commands ports.ControlRepository
	evidence ports.EvidenceRepository
	audits   ports.ControlAuditRepository
}

func (stub controlTransactionStub) Commands() ports.ControlRepository    { return stub.commands }
func (stub controlTransactionStub) Evidence() ports.EvidenceRepository   { return stub.evidence }
func (stub controlTransactionStub) Audits() ports.ControlAuditRepository { return stub.audits }

type commandRepositoryStub struct {
	current    domaincontrol.Command
	next       domaincontrol.Command
	puts       int
	creates    int
	listed     []domaincontrol.Command
	listTenant tenant.ID
}

func (stub *commandRepositoryStub) List(_ context.Context, tenantID tenant.ID, _ ports.ControlFilter) ([]domaincontrol.Command, error) {
	stub.listTenant = tenantID
	return stub.listed, nil
}

func (stub *commandRepositoryStub) Get(context.Context, tenant.ID, string) (domaincontrol.Command, error) {
	return stub.current, nil
}

func (stub *commandRepositoryStub) Put(_ context.Context, _, next domaincontrol.Command) error {
	stub.puts++
	stub.next = next
	return nil
}

func (stub *commandRepositoryStub) Create(_ context.Context, value domaincontrol.Command) (domaincontrol.Command, error) {
	stub.creates++
	stub.current = value
	return value, nil
}

type evidenceRepositoryStub struct {
	current    domaincontrol.EvidencePullback
	puts       int
	creates    int
	listed     []domaincontrol.EvidencePullback
	listTenant tenant.ID
}

func (stub *evidenceRepositoryStub) List(_ context.Context, tenantID tenant.ID, _ ports.EvidenceFilter) ([]domaincontrol.EvidencePullback, error) {
	stub.listTenant = tenantID
	return stub.listed, nil
}

func (stub *evidenceRepositoryStub) Get(context.Context, tenant.ID, string) (domaincontrol.EvidencePullback, error) {
	return stub.current, nil
}

func (stub *evidenceRepositoryStub) Put(_ context.Context, _, _ domaincontrol.EvidencePullback) error {
	stub.puts++
	return nil
}

func (stub *evidenceRepositoryStub) Create(_ context.Context, value domaincontrol.EvidencePullback) (domaincontrol.EvidencePullback, error) {
	stub.creates++
	stub.current = value
	return value, nil
}

type controlAuditRepositoryStub struct {
	appends int
	last    domaincontrol.AuditRecord
}

func (stub *controlAuditRepositoryStub) Append(_ context.Context, value domaincontrol.AuditRecord) error {
	stub.appends++
	stub.last = value
	return nil
}

type clockStub struct{ now time.Time }

func (stub clockStub) Now() time.Time { return stub.now }

type idGeneratorStub struct {
	values []string
	index  int
}

func (stub *idGeneratorStub) New() string {
	value := stub.values[stub.index]
	stub.index++
	return value
}

func adminControlRequest(t *testing.T) managerapp.RequestContext {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleAdmin),
	}}
}
