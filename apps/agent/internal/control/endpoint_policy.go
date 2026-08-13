package control

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type PolicyIdentity struct {
	TenantID string
	AgentID  string
}

type EndpointPolicySettings struct {
	TenantID     string
	Telemetry    config.TelemetryConfig
	Capabilities []contract.CollectionBehaviorCapability
	Limits       detection.EngineLimits
}

type PreparedEndpointPolicy struct {
	Endpoint  agentpolicy.EndpointPolicy
	Intent    contract.CollectionIntent
	Runtime   policymodel.Policy
	Detection *detection.Engine
	Report    detection.ApplyReport
	Telemetry config.EffectiveTelemetry
	Compile   contract.CollectionCompileReport
}

type EndpointPolicyRuntime interface {
	PolicyIdentity() PolicyIdentity
	ValidatePolicyContext(RequestContext) error
	BeginLocalPolicyMutation(context.Context, bool) (func(), error)
	WithEndpointDetectionUpdate(func())
	WithManagedPolicyTransition(func())
	EndpointPolicySettings() EndpointPolicySettings
	EndpointCollectionContent() agentpolicy.CollectionContentSnapshot
	EndpointDetectionContent() detection.ContentSnapshot
	CurrentEndpointIntent() contract.CollectionIntent
	ApplyEndpointIntent(context.Context, contract.CollectionIntent) error
	PersistEndpointPolicy(context.Context, PolicySource, agentpolicy.EndpointPolicy) error
	SaveDesiredManagedEndpointPolicy(context.Context, agentpolicy.EndpointPolicy) error
	ActivateManagedEndpointPolicy(context.Context, agentpolicy.EndpointPolicy) error
	SetPendingEndpointPolicy(PreparedEndpointPolicy)
	PendingEndpointPolicy() *PreparedEndpointPolicy
	ClearPendingEndpointPolicy()
	ActivatePreparedEndpointPolicy(PreparedEndpointPolicy)
	PromoteManagedAuthority(context.Context) error
	LoadEndpointPolicy(context.Context, PolicySource) (agentpolicy.EndpointPolicy, bool, error)
	DesiredManagedEndpointPolicy(context.Context) (localstore.PolicyRecord, localstore.PolicyStatus, bool, error)
}

type EndpointPolicyController struct {
	runtime EndpointPolicyRuntime
}

func NewEndpointPolicyController(runtime EndpointPolicyRuntime) *EndpointPolicyController {
	return &EndpointPolicyController{runtime: runtime}
}

func (c *EndpointPolicyController) Apply(ctx context.Context, command PolicyCommand) Result {
	identity := c.runtime.PolicyIdentity()
	if err := c.runtime.ValidatePolicyContext(command.Context); err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
	}
	if command.Source == PolicySourceManaged {
		return c.applyManaged(ctx, command, identity)
	}
	release, err := c.runtime.BeginLocalPolicyMutation(ctx, !command.DryRun)
	if err != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "endpoint", err.Error())
	}
	defer release()
	return c.applyStandalone(ctx, command, identity)
}

func (c *EndpointPolicyController) applyStandalone(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	var result Result
	c.runtime.WithEndpointDetectionUpdate(func() {
		prepared, err := c.prepare(command.Document)
		if err != nil {
			result = rejectedPolicyResult(identity, command.Context.RequestID, "policy", err.Error())
			return
		}
		if command.DryRun {
			result = endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, "validated", "endpoint policy accepted in dry-run", true)
			return
		}
		previous := c.runtime.CurrentEndpointIntent()
		if err := c.runtime.ApplyEndpointIntent(ctx, prepared.Intent); err != nil {
			result = rejectedPolicyResult(identity, command.Context.RequestID, "collection", "apply collection policy: "+err.Error())
			return
		}
		if err := c.runtime.PersistEndpointPolicy(ctx, PolicySourceStandalone, prepared.Endpoint); err != nil {
			_ = c.runtime.ApplyEndpointIntent(ctx, previous)
			result = rejectedPolicyResult(identity, command.Context.RequestID, "policy", "persist endpoint policy: "+err.Error())
			return
		}
		c.runtime.ActivatePreparedEndpointPolicy(prepared)
		result = endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, prepared.Report.Status, "endpoint policy applied", true)
	})
	return result
}

func (c *EndpointPolicyController) applyManaged(ctx context.Context, command PolicyCommand, identity PolicyIdentity) Result {
	var prepared PreparedEndpointPolicy
	var prepareErr error
	c.runtime.WithManagedPolicyTransition(func() {
		prepared, prepareErr = c.prepare(command.Document)
		if prepareErr == nil && !command.DryRun {
			prepareErr = c.runtime.SaveDesiredManagedEndpointPolicy(ctx, prepared.Endpoint)
			if prepareErr == nil {
				c.runtime.SetPendingEndpointPolicy(prepared)
			}
		}
	})
	if prepareErr != nil {
		return rejectedPolicyResult(identity, command.Context.RequestID, "policy", prepareErr.Error())
	}
	if command.DryRun {
		return endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, "validated", "endpoint policy accepted in dry-run", true)
	}
	if err := c.runtime.ApplyEndpointIntent(ctx, prepared.Intent); err != nil {
		return endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, "pending", "endpoint policy persisted; waiting for sensor recovery", false)
	}
	if err := c.CompletePending(ctx, prepared.Intent); err != nil {
		return endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, "pending", "endpoint policy persisted; waiting for durable activation", false)
	}
	return endpointPolicyResult(identity, command.Context.RequestID, prepared.Runtime, prepared.Report.Status, "endpoint policy applied", true)
}

func (c *EndpointPolicyController) CompletePending(ctx context.Context, intent contract.CollectionIntent) error {
	var completeErr error
	c.runtime.WithManagedPolicyTransition(func() {
		pending := c.runtime.PendingEndpointPolicy()
		if pending == nil || !reflect.DeepEqual(pending.Intent, intent) {
			return
		}
		if completeErr = c.runtime.ActivateManagedEndpointPolicy(ctx, pending.Endpoint); completeErr != nil {
			return
		}
		c.runtime.ActivatePreparedEndpointPolicy(*pending)
		c.runtime.ClearPendingEndpointPolicy()
		completeErr = c.runtime.PromoteManagedAuthority(ctx)
	})
	return completeErr
}

func (c *EndpointPolicyController) Prepare(document string) (PreparedEndpointPolicy, error) {
	return c.prepare(document)
}

func (c *EndpointPolicyController) LoadPending(ctx context.Context) (PreparedEndpointPolicy, bool, error) {
	record, status, ok, err := c.runtime.DesiredManagedEndpointPolicy(ctx)
	if err != nil || !ok || status != localstore.PolicyStatusPending {
		return PreparedEndpointPolicy{}, false, err
	}
	prepared, err := c.prepare(string(record.Document))
	if err != nil {
		return PreparedEndpointPolicy{}, false, fmt.Errorf("prepare pending managed endpoint policy: %w", err)
	}
	return prepared, true, nil
}

func (c *EndpointPolicyController) RestoreStandalone(ctx context.Context, activate func(context.Context) error) error {
	policy, ok, err := c.runtime.LoadEndpointPolicy(ctx, PolicySourceStandalone)
	if err != nil {
		return fmt.Errorf("load standalone endpoint policy: %w", err)
	}
	if !ok {
		return fmt.Errorf("standalone endpoint policy is not initialized")
	}
	document, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("encode standalone endpoint policy: %w", err)
	}
	var restoreErr error
	c.runtime.WithEndpointDetectionUpdate(func() {
		prepared, err := c.prepare(string(document))
		if err != nil {
			restoreErr = fmt.Errorf("prepare standalone endpoint policy: %w", err)
			return
		}
		previous := c.runtime.CurrentEndpointIntent()
		if err := ApplyAndActivateEndpointIntent(ctx, previous, prepared.Intent, c.runtime.ApplyEndpointIntent, activate); err != nil {
			restoreErr = fmt.Errorf("restore standalone endpoint policy: %w", err)
			return
		}
		c.runtime.ActivatePreparedEndpointPolicy(prepared)
	})
	return restoreErr
}

func ApplyAndActivateEndpointIntent(ctx context.Context, previous, next contract.CollectionIntent, apply func(context.Context, contract.CollectionIntent) error, activate func(context.Context) error) error {
	if err := apply(ctx, next); err != nil {
		return fmt.Errorf("apply sensor intent: %w", err)
	}
	if err := activate(ctx); err != nil {
		if rollbackErr := apply(ctx, previous); rollbackErr != nil {
			return fmt.Errorf("activate policy: %w; rollback sensor intent: %v", err, rollbackErr)
		}
		return fmt.Errorf("activate policy: %w", err)
	}
	return nil
}
