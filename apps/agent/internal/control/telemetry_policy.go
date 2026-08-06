package control

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type TelemetryPolicyRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	TelemetryPolicyBaseline() config.TelemetryConfig
	PersistTelemetryPolicy(context.Context, policymodel.TelemetryPolicy) error
	ActivateTelemetryPolicy(config.EffectiveTelemetry)
}

type TelemetryPolicyController struct {
	runtime TelemetryPolicyRuntime
}

func NewTelemetryPolicyController(runtime TelemetryPolicyRuntime) *TelemetryPolicyController {
	return &TelemetryPolicyController{runtime: runtime}
}

func (c *TelemetryPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.runtime.PolicyIdentity()
	if err := c.runtime.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	release, err := c.runtime.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
	}
	defer release()
	policy, effective, err := c.prepare(command)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
	}
	if command.DryRun {
		return telemetryPolicyResult(identity, command.Context.RequestID, "validated", "telemetry policy accepted in dry-run", policy)
	}
	if err := c.runtime.PersistTelemetryPolicy(ctx, policy); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "telemetry", err.Error())
	}
	c.runtime.ActivateTelemetryPolicy(effective)
	return telemetryPolicyResult(identity, command.Context.RequestID, "applied", "telemetry policy applied", policy)
}

func (c *TelemetryPolicyController) prepare(command PolicyCommand) (policymodel.TelemetryPolicy, config.EffectiveTelemetry, error) {
	policy, err := parseTelemetryPolicy(command)
	if err != nil {
		return policymodel.TelemetryPolicy{}, config.EffectiveTelemetry{}, err
	}
	if _, err := config.ResolveTelemetry(config.DefaultTelemetryConfig(), &policy); err != nil {
		return policymodel.TelemetryPolicy{}, config.EffectiveTelemetry{}, err
	}
	effective, err := config.ResolveTelemetry(c.runtime.TelemetryPolicyBaseline(), &policy)
	return policy, effective, err
}

func parseTelemetryPolicy(command PolicyCommand) (policymodel.TelemetryPolicy, error) {
	var policy *policymodel.TelemetryPolicy
	if strings.TrimSpace(command.Document) != "" {
		parsed, err := parseTelemetryDocument(command.Document)
		if err != nil {
			return policymodel.TelemetryPolicy{}, err
		}
		policy = &parsed
	}
	if command.Telemetry != nil {
		policy = &policymodel.TelemetryPolicy{
			MaxBatchItems: int(command.Telemetry.MaxBatchItems), MaxBatchBytes: int(command.Telemetry.MaxBatchBytes),
			FlushInterval: command.Telemetry.FlushInterval,
		}
	}
	if policy == nil {
		return policymodel.TelemetryPolicy{}, fmt.Errorf("telemetry policy is required")
	}
	return *policy, nil
}

func parseTelemetryDocument(document string) (policymodel.TelemetryPolicy, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &raw); err != nil {
		return policymodel.TelemetryPolicy{}, fmt.Errorf("invalid telemetry policy json: %w", err)
	}
	payload := []byte(document)
	if nested, ok := raw["telemetry"]; ok {
		payload = nested
	}
	var policy policymodel.TelemetryPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return policymodel.TelemetryPolicy{}, fmt.Errorf("invalid telemetry policy json: %w", err)
	}
	return policy, nil
}
