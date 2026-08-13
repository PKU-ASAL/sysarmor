package daemon

import (
	"context"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type collectionPolicyRuntime struct {
	runner  *AgentRuntime
	runtime sensorruntime.Runtime
}

func newCollectionPolicyRuntime(runner *AgentRuntime, runtime sensorruntime.Runtime) *collectionPolicyRuntime {
	return &collectionPolicyRuntime{runner: runner, runtime: runtime}
}

func (r *collectionPolicyRuntime) PolicyIdentity() agentcontrol.PolicyIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.PolicyIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *collectionPolicyRuntime) ValidatePolicyContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *collectionPolicyRuntime) BeginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *collectionPolicyRuntime) WithCollectionPolicyUpdate(run func()) {
	r.runner.withDetectionUpdateTransaction(run)
}

func (r *collectionPolicyRuntime) CollectionObserveOnly() bool {
	return r.runner.Config.Sensor.ObserveOnly
}

func (r *collectionPolicyRuntime) CollectionDefaultScope() agentcontrol.Scope {
	scope, err := r.runner.Config.Sensor.EffectiveScope()
	if err != nil {
		return agentcontrol.Scope{}
	}
	return agentcontrol.Scope{Type: scope.Type, Selector: scope.Selector}
}

func (r *collectionPolicyRuntime) CollectionContent() agentpolicy.CollectionContentSnapshot {
	return collectionContentSnapshot(r.runner.contentStore().Snapshot())
}

func (r *collectionPolicyRuntime) ActiveCollectionDetectionPolicy() policymodel.Policy {
	return r.runner.activePolicy()
}

func (r *collectionPolicyRuntime) CollectionCapabilities() []contract.CollectionBehaviorCapability {
	return append([]contract.CollectionBehaviorCapability(nil), r.runner.capability.Collection...)
}

func (r *collectionPolicyRuntime) CollectionDetectionContent() detection.ContentSnapshot {
	return r.runner.detectionContentSnapshot()
}

func (r *collectionPolicyRuntime) CollectionDetectionLimits() detection.EngineLimits {
	return r.runner.detectionLimits()
}

func (r *collectionPolicyRuntime) CurrentCollectionIntent() contract.CollectionIntent {
	return r.runner.currentCollectionIntent()
}

func (r *collectionPolicyRuntime) ApplyCollectionIntent(ctx context.Context, intent contract.CollectionIntent) error {
	reconciler := endpointPolicyReconciler{runtime: r.runtime, supervisor: r.runner.currentSensorSupervisor()}
	_, err := reconciler.Apply(ctx, intent)
	return err
}

func (r *collectionPolicyRuntime) PersistCollectionPolicy(ctx context.Context, policy agentpolicy.CollectionPolicy) error {
	if r.runner.localStore == nil {
		return nil
	}
	endpoint := r.runner.currentEndpointPolicy()
	endpoint.Collection = policy
	endpoint.Version++
	return r.runner.persistEndpointPolicy(ctx, localstore.PolicySourceStandalone, endpoint)
}

func (r *collectionPolicyRuntime) ActivateCollectionPolicy(intent contract.CollectionIntent, engine *detection.Engine) {
	r.runner.setCollectionIntent(intent)
	r.runner.setDetection(engine)
}
