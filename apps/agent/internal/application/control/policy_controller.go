package control

import (
	"context"
	"fmt"
	"strings"
)

type PolicyUseCase interface {
	Apply(context.Context, PolicyCommand) Result
}

type PolicyUseCases struct {
	StandaloneEndpoint PolicyUseCase
	ManagedEndpoint    PolicyUseCase
	Collection         PolicyUseCase
	Detection          PolicyUseCase
	Telemetry          PolicyUseCase
}

type ApplicationPolicyController struct {
	runtime  PolicyControllerRuntime
	useCases PolicyUseCases
}

func NewApplicationPolicyController(runtime PolicyControllerRuntime, useCases PolicyUseCases) *ApplicationPolicyController {
	return &ApplicationPolicyController{runtime: runtime, useCases: useCases}
}

func (c *ApplicationPolicyController) ApplyPolicy(ctx context.Context, command PolicyCommand) Result {
	policyType := strings.TrimSpace(command.PolicyType)
	if policyType == "" {
		policyType = "endpoint"
	}
	if command.Source == PolicySourceManaged {
		command.PolicyType = "endpoint"
		return c.useCases.ManagedEndpoint.Apply(ctx, command)
	}
	command.PolicyType = policyType
	switch policyType {
	case "endpoint":
		return c.useCases.StandaloneEndpoint.Apply(ctx, command)
	case "collection":
		return c.useCases.Collection.Apply(ctx, command)
	case "detection":
		return c.useCases.Detection.Apply(ctx, command)
	case "telemetry":
		return c.useCases.Telemetry.Apply(ctx, command)
	default:
		return c.rejectUnsupported(ctx, command, policyType)
	}
}

func (c *ApplicationPolicyController) rejectUnsupported(ctx context.Context, command PolicyCommand, policyType string) Result {
	identity := c.runtime.PolicyIdentity()
	if err := c.runtime.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.runtime.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, policyType, err.Error())
	}
	defer release()
	message := fmt.Sprintf("unsupported policy type %q", policyType)
	return rejectedPolicyResult(identity, command.Context.RequestID, "policy", message)
}
