package control

import (
	"context"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type DetectionApplication interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	ValidateDetection(context.Context, string) (applicationpolicy.DetectionCandidate, error)
	ActivateDetection(context.Context, string) (applicationpolicy.DetectionResult, error)
}

type DetectionPolicyController struct{ application DetectionApplication }

func NewDetectionPolicyController(application DetectionApplication) *DetectionPolicyController {
	return &DetectionPolicyController{application: application}
}

func (c *DetectionPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.application.PolicyIdentity()
	if err := c.application.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.application.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "detection", err.Error())
	}
	defer release()
	if command.DryRun {
		candidate, err := c.application.ValidateDetection(ctx, command.Document)
		if err != nil {
			return rejectedPolicyResult(identity, command.Context.RequestID, "detection", err.Error())
		}
		return detectionApplicationResult(identity, command.Context.RequestID, candidate, candidate.BuildReport())
	}
	result, err := c.application.ActivateDetection(ctx, command.Document)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "detection", err.Error())
	}
	return detectionApplicationResult(identity, command.Context.RequestID, result.Candidate, result.Report)
}
