package control

import (
	"context"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type TelemetryApplication interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	ValidateTelemetry(context.Context, string, *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error)
	ActivateTelemetry(context.Context, string, *applicationpolicy.TelemetryInput) (applicationpolicy.TelemetryCandidate, error)
}

type TelemetryPolicyController struct{ application TelemetryApplication }

func NewTelemetryPolicyController(application TelemetryApplication) *TelemetryPolicyController {
	return &TelemetryPolicyController{application: application}
}

func (c *TelemetryPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.application.PolicyIdentity()
	if err := c.application.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.application.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
	}
	defer release()
	input := telemetryApplicationInput(command.Telemetry)
	if command.DryRun {
		candidate, err := c.application.ValidateTelemetry(ctx, command.Document, input)
		if err != nil {
			return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
		}
		return telemetryApplicationResult(identity, command.Context.RequestID, "validated", "telemetry policy accepted in dry-run", candidate)
	}
	candidate, err := c.application.ActivateTelemetry(ctx, command.Document, input)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
	}
	return telemetryApplicationResult(identity, command.Context.RequestID, "applied", "telemetry policy applied", candidate)
}

func telemetryApplicationInput(policy *TelemetryPolicy) *applicationpolicy.TelemetryInput {
	if policy == nil {
		return nil
	}
	return &applicationpolicy.TelemetryInput{
		MaxBatchItems: policy.MaxBatchItems, MaxBatchBytes: policy.MaxBatchBytes, FlushInterval: policy.FlushInterval,
	}
}
