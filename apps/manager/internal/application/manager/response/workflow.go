package response

import (
	"context"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type Preparation struct {
	Policy        domainresponse.Policy
	Runtime       domainresponse.Scope
	RuntimeKnown  bool
	PolicyID      string
	PolicyVersion uint64
}

type PreparationResolver interface {
	Resolve(context.Context, managerapp.RequestContext, domainresponse.Command) (Preparation, error)
}

type SignalResolver interface {
	Resolve(context.Context, managerapp.RequestContext, DecisionCommand) (domainresponse.Command, error)
}

type Workflow struct {
	core        *Service
	preparation PreparationResolver
	signals     SignalResolver
}

func NewWorkflow(core *Service, preparation PreparationResolver, signals SignalResolver) *Workflow {
	return &Workflow{core: core, preparation: preparation, signals: signals}
}

func (workflow *Workflow) Create(ctx context.Context, request managerapp.RequestContext, command domainresponse.Command) (domainresponse.PrepareResult, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainresponse.PrepareResult{}, err
	}
	if workflow == nil || workflow.core == nil || workflow.preparation == nil {
		return domainresponse.PrepareResult{}, failure.New(failure.Internal, "response workflow is incomplete")
	}
	preparation, err := workflow.preparation.Resolve(ctx, request, command)
	if err != nil {
		return domainresponse.PrepareResult{}, err
	}
	if command.PolicyID == "" {
		command.PolicyID, command.PolicyVersion = preparation.PolicyID, preparation.PolicyVersion
	}
	if command.Scope.Type == "" && command.Scope.Selector == "" && preparation.RuntimeKnown {
		command.Scope = preparation.Runtime
	}
	return workflow.core.Create(ctx, request, CreateCommand{
		Value: command, Policy: preparation.Policy, Runtime: preparation.Runtime, RuntimeKnown: preparation.RuntimeKnown,
	})
}

func (workflow *Workflow) Decide(ctx context.Context, request managerapp.RequestContext, query DecisionCommand) (domainresponse.PrepareResult, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return domainresponse.PrepareResult{}, err
	}
	if workflow == nil || workflow.signals == nil {
		return domainresponse.PrepareResult{}, failure.New(failure.Internal, "response signal resolver is required")
	}
	command, err := workflow.signals.Resolve(ctx, request, query)
	if err != nil {
		return domainresponse.PrepareResult{}, err
	}
	return workflow.Create(ctx, request, command)
}

func (workflow *Workflow) Approve(ctx context.Context, request managerapp.RequestContext, command ApprovalCommand) (domainresponse.Command, error) {
	return workflow.core.Approve(ctx, request, command)
}

func (workflow *Workflow) Acknowledge(ctx context.Context, command AcknowledgeCommand) (domainresponse.Acknowledged, error) {
	return workflow.core.Acknowledge(ctx, command)
}

func (workflow *Workflow) List(ctx context.Context, request managerapp.RequestContext, query Query) ([]domainresponse.Command, error) {
	return workflow.core.List(ctx, request, query)
}
