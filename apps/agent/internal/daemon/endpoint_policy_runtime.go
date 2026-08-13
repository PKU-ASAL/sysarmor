package daemon

import (
	"context"
	"fmt"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type endpointPolicyRuntime struct {
	runner  *AgentRuntime
	runtime sensorruntime.Runtime
	batcher *telemetry.Batcher
}

func newEndpointPolicyRuntime(runner *AgentRuntime, runtime sensorruntime.Runtime, batcher *telemetry.Batcher) *endpointPolicyRuntime {
	return &endpointPolicyRuntime{runner: runner, runtime: runtime, batcher: batcher}
}

func (r *endpointPolicyRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *endpointPolicyRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *endpointPolicyRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *endpointPolicyRuntime) WithEndpointDetectionUpdate(run func()) {
	r.runner.withDetectionUpdateTransaction(run)
}

func (r *endpointPolicyRuntime) WithManagedPolicyTransition(run func()) {
	r.runner.policyAuthorityMu.Lock()
	defer r.runner.policyAuthorityMu.Unlock()
	r.runner.withDetectionUpdateTransaction(run)
}

func (r *endpointPolicyRuntime) EndpointPolicySettings() agentcontrol.EndpointPolicySettings {
	identity := r.runner.currentIdentity()
	return agentcontrol.EndpointPolicySettings{
		TenantID: identity.TenantID, Telemetry: r.runner.Config.Telemetry,
		Capabilities: append([]contract.CollectionBehaviorCapability(nil), r.runner.capability.Collection...),
		Limits:       r.runner.detectionLimits(),
	}
}

func (r *endpointPolicyRuntime) EndpointCollectionContent() agentpolicy.CollectionContentSnapshot {
	return collectionContentSnapshot(r.runner.contentStore().Snapshot())
}

func (r *endpointPolicyRuntime) EndpointDetectionContent() detection.ContentSnapshot {
	return r.runner.detectionContentSnapshot()
}

func (r *endpointPolicyRuntime) CurrentEndpointIntent() contract.CollectionIntent {
	return r.runner.currentCollectionIntent()
}

func (r *endpointPolicyRuntime) ApplyEndpointIntent(ctx context.Context, intent contract.CollectionIntent) error {
	reconciler := endpointPolicyReconciler{runtime: r.runtime, supervisor: r.runner.currentSensorSupervisor()}
	_, err := reconciler.Apply(ctx, intent)
	return err
}

func (r *endpointPolicyRuntime) PersistEndpointPolicy(ctx context.Context, source agentcontrol.PolicySource, policy agentpolicy.EndpointPolicy) error {
	return r.runner.persistEndpointPolicy(ctx, localstore.PolicySource(source), policy)
}

func (r *endpointPolicyRuntime) SaveDesiredManagedEndpointPolicy(ctx context.Context, policy agentpolicy.EndpointPolicy) error {
	if r.runner.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	return agentpolicy.SaveDesiredManagedEndpointPolicy(ctx, r.runner.localStore, policy)
}

func (r *endpointPolicyRuntime) ActivateManagedEndpointPolicy(ctx context.Context, policy agentpolicy.EndpointPolicy) error {
	if r.runner.localStore == nil {
		return fmt.Errorf("local store is unavailable")
	}
	return agentpolicy.ActivateManagedEndpointPolicy(ctx, r.runner.localStore, policy)
}

func (r *endpointPolicyRuntime) SetPendingEndpointPolicy(policy agentcontrol.PreparedEndpointPolicy) {
	r.runner.mu.Lock()
	defer r.runner.mu.Unlock()
	r.runner.pendingEndpoint = &policy
}

func (r *endpointPolicyRuntime) PendingEndpointPolicy() *agentcontrol.PreparedEndpointPolicy {
	r.runner.mu.RLock()
	defer r.runner.mu.RUnlock()
	if r.runner.pendingEndpoint == nil {
		return nil
	}
	pending := *r.runner.pendingEndpoint
	return &pending
}

func (r *endpointPolicyRuntime) ClearPendingEndpointPolicy() {
	r.runner.mu.Lock()
	r.runner.pendingEndpoint = nil
	r.runner.mu.Unlock()
}

func (r *endpointPolicyRuntime) ActivatePreparedEndpointPolicy(policy agentcontrol.PreparedEndpointPolicy) {
	r.runner.setEndpointPolicy(policy.Endpoint)
	r.runner.setCollectionIntent(policy.Intent)
	r.runner.setPolicy(policy.Runtime)
	r.runner.setDetection(policy.Detection)
	r.runner.setDetectionStatus(policy.Runtime, policy.Report, r.runner.contentStore().Snapshot())
	r.runner.setEffectiveTelemetry(policy.Telemetry)
	if r.batcher != nil {
		r.batcher.Reconfigure(telemetry.BatchSettings{
			MaxItems: policy.Telemetry.MaxBatchItems, MaxBytes: policy.Telemetry.MaxBatchBytes,
			FlushInterval: policy.Telemetry.FlushInterval,
		})
	}
}

func (r *endpointPolicyRuntime) PromoteManagedAuthority(ctx context.Context) error {
	if r.runner.localStore == nil {
		return nil
	}
	enrollment, err := r.runner.localStore.Enrollment(ctx)
	if err != nil {
		return fmt.Errorf("read enrollment for managed policy activation: %w", err)
	}
	if enrollment.State != localstore.StateManaged {
		return fmt.Errorf("managed policy authority promotion requires managed enrollment, got %s", enrollment.State)
	}
	return r.runner.reconcileManagementContext(enrollment)
}

func (r *endpointPolicyRuntime) LoadEndpointPolicy(ctx context.Context, source agentcontrol.PolicySource) (agentpolicy.EndpointPolicy, bool, error) {
	if r.runner.localStore == nil {
		return agentpolicy.EndpointPolicy{}, false, nil
	}
	return agentpolicy.LoadEndpointPolicy(ctx, r.runner.localStore, localstore.PolicySource(source))
}

func (r *endpointPolicyRuntime) DesiredManagedEndpointPolicy(ctx context.Context) (localstore.PolicyRecord, localstore.PolicyStatus, bool, error) {
	if r.runner.localStore == nil {
		return localstore.PolicyRecord{}, "", false, nil
	}
	return r.runner.localStore.DesiredPolicy(ctx, "endpoint", localstore.PolicySourceManaged)
}

func (r *AgentRuntime) beginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	if !mutation {
		return func() {}, nil
	}
	r.policyAuthorityMu.RLock()
	if r.localStore == nil {
		r.policyAuthorityMu.RUnlock()
		return nil, fmt.Errorf("local store is unavailable")
	}
	enrollment, err := r.localStore.Enrollment(ctx)
	if err != nil {
		r.policyAuthorityMu.RUnlock()
		return nil, fmt.Errorf("read enrollment state: %w", err)
	}
	mode, err := management.Resolve(enrollment.State)
	if err == nil {
		err = mode.Authorize(management.PolicyWriteLocal)
	}
	if err != nil {
		r.policyAuthorityMu.RUnlock()
		return nil, err
	}
	return r.policyAuthorityMu.RUnlock, nil
}
