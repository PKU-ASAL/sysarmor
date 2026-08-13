package control

import (
	"context"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type CollectionApplication interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	ValidateCollection(context.Context, string, applicationpolicy.CollectionScope) (applicationpolicy.CollectionCandidate, error)
	ActivateCollection(context.Context, string, applicationpolicy.CollectionScope) (applicationpolicy.CollectionResult, error)
}

type CollectionPolicyController struct {
	application CollectionApplication
}

func NewCollectionPolicyController(application CollectionApplication) *CollectionPolicyController {
	return &CollectionPolicyController{application: application}
}

func (c *CollectionPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.application.PolicyIdentity()
	if err := c.application.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.application.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "collection", err.Error())
	}
	defer release()
	scope := collectionApplicationScope(command.Context.Scope)
	if command.DryRun {
		candidate, err := c.application.ValidateCollection(ctx, command.Document, scope)
		if err != nil {
			return rejectedPolicyResult(identity, command.Context.RequestID, "collection", err.Error())
		}
		return collectionApplicationResult(identity, command.Context.RequestID, candidate, candidate.ValidationReport())
	}
	result, err := c.application.ActivateCollection(ctx, command.Document, scope)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "collection", err.Error())
	}
	return collectionApplicationResult(identity, command.Context.RequestID, result.Candidate, result.Report)
}

func collectionApplicationScope(scope *Scope) applicationpolicy.CollectionScope {
	if scope == nil {
		return applicationpolicy.CollectionScope{}
	}
	return applicationpolicy.CollectionScope{Type: scope.Type, Selector: scope.Selector}
}
