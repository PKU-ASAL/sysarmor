package control

import (
	"context"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type PolicyIdentity struct {
	TenantID string
	AgentID  string
}

type EndpointApplication interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	ValidateEndpoint(context.Context, string, applicationpolicy.Source) (applicationpolicy.EndpointCandidate, error)
	ActivateStandaloneEndpoint(context.Context, string) (applicationpolicy.EndpointResult, error)
	ActivateManagedEndpoint(context.Context, string) (applicationpolicy.EndpointResult, error)
}

type EndpointPolicyController struct {
	application EndpointApplication
}

func NewEndpointPolicyController(application EndpointApplication) *EndpointPolicyController {
	return &EndpointPolicyController{application: application}
}

func (c *EndpointPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.application.PolicyIdentity()
	if err := c.application.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	if command.Source == PolicySourceManaged {
		return c.applyManaged(ctx, command, identity)
	}
	release, err := c.application.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "endpoint", err.Error())
	}
	defer release()
	return c.applyStandalone(ctx, command, identity)
}

func (c *EndpointPolicyController) applyStandalone(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	if command.DryRun {
		candidate, err := c.application.ValidateEndpoint(ctx, command.Document, applicationpolicy.SourceStandalone)
		if err != nil {
			return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
		}
		return endpointApplicationResult(identity, command.Context.RequestID, candidate, applicationpolicy.EndpointReport{Status: "validated", Message: "endpoint policy accepted in dry-run"})
	}
	result, err := c.application.ActivateStandaloneEndpoint(ctx, command.Document)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	return endpointApplicationResult(identity, command.Context.RequestID, result.Candidate, result.Report)
}

func (c *EndpointPolicyController) applyManaged(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	if command.DryRun {
		candidate, err := c.application.ValidateEndpoint(ctx, command.Document, applicationpolicy.SourceManaged)
		if err != nil {
			return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
		}
		return endpointApplicationResult(identity, command.Context.RequestID, candidate, applicationpolicy.EndpointReport{Status: "validated", Message: "endpoint policy accepted in dry-run"})
	}
	result, err := c.application.ActivateManagedEndpoint(ctx, command.Document)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	return endpointApplicationResult(identity, command.Context.RequestID, result.Candidate, result.Report)
}
