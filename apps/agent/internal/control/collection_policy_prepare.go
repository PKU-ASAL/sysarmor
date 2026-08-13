package control

import (
	"fmt"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type PreparedCollectionPolicy struct {
	Policy    agentpolicy.CollectionPolicy
	Intent    contract.CollectionIntent
	Compile   contract.CollectionCompileReport
	Detection detection.ApplyReport
}

func (c *CollectionPolicyController) prepare(command PolicyCommand) (PreparedCollectionPolicy, error) {
	policy, err := agentpolicy.ParseCollectionPolicyJSON([]byte(command.Document), c.runtime.CollectionObserveOnly())
	if err != nil {
		return PreparedCollectionPolicy{}, fmt.Errorf("invalid collection policy: %w", err)
	}
	applyCollectionScope(&policy, command.Context.Scope, c.runtime.CollectionDefaultScope())
	policy, expansion, err := agentpolicy.ExpandCollectionPolicyRefs(policy, c.runtime.CollectionContent())
	if err != nil {
		return PreparedCollectionPolicy{}, fmt.Errorf("resolve collection policy refs: %w", err)
	}
	intent, err := agentpolicy.CollectionPolicyIntent(policy)
	if err != nil {
		return PreparedCollectionPolicy{}, fmt.Errorf("compile collection policy: %w", err)
	}
	compile := tetragon.CompileReport(intent)
	compile.ResolvedRefs = expansion.ResolvedRefs
	detectionIntent := intent
	if len(detectionIntent.Capabilities) == 0 {
		detectionIntent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), c.runtime.CollectionCapabilities()...)
	}
	_, report := detection.NewWithRuntimeLimits(c.runtime.ActiveCollectionDetectionPolicy().Detection, detectionIntent, c.runtime.CollectionDetectionContent(), c.runtime.CollectionDetectionLimits())
	return PreparedCollectionPolicy{Policy: policy, Intent: intent, Compile: compile, Detection: report}, nil
}

func applyCollectionScope(policy *agentpolicy.CollectionPolicy, requested *Scope, fallback Scope) {
	if policy.ScopeType == "" && requested != nil && requested.Type != "" {
		policy.ScopeType = requested.Type
		policy.ScopeSelector = requested.Selector
	}
	if policy.ScopeType == "" {
		policy.ScopeType = fallback.Type
		policy.ScopeSelector = fallback.Selector
	}
}
