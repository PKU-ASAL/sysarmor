package control

import (
	"context"
)

type PolicyControllerRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	CurrentPolicySnapshot(context.Context) (PolicySnapshot, error)
}

func (c *ApplicationPolicyController) CurrentPolicy(ctx context.Context) (PolicySnapshot, error) {
	return c.runtime.CurrentPolicySnapshot(ctx)
}
