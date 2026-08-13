package daemon

import (
	"reflect"
	"strings"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (r *AgentRuntime) activePolicy() policymodel.Policy {
	r.mu.RLock()
	policy := r.policy
	r.mu.RUnlock()
	if policy.PolicyID != "" {
		return policy
	}
	return policymodel.DefaultPolicy(r.currentIdentity().TenantID)
}

func (r *AgentRuntime) setPolicy(policy policymodel.Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = policy
}

func (r *AgentRuntime) currentDetection() *detection.Engine {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.detection != nil {
		return r.detection
	}
	engine, _ := detection.NewWithRuntimeLimits(policymodel.DefaultDetectionPolicy(), r.collection, detection.ContentSnapshot{}, r.detectionLimits())
	return engine
}

func (r *AgentRuntime) setDetection(engine *detection.Engine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detection = engine
}

func (r *AgentRuntime) setCollectionIntent(intent contract.CollectionIntent) {
	intent = r.withCollectionCapabilities(intent)
	r.mu.Lock()
	r.collection = intent
	r.mu.Unlock()
}

func (r *AgentRuntime) setSensorSupervisor(supervisor *sensorruntime.SubscriptionSupervisor) {
	r.mu.Lock()
	r.sensorSupervisor = supervisor
	intent := r.collection
	r.mu.Unlock()
	supervisor.UpdateIntent(intent)
}

func (r *AgentRuntime) currentCollectionIntent() contract.CollectionIntent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.collection
}

func (r *AgentRuntime) withCollectionCapabilities(intent contract.CollectionIntent) contract.CollectionIntent {
	if len(intent.Capabilities) == 0 && len(r.capability.Collection) > 0 {
		intent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), r.capability.Collection...)
	}
	return intent
}

func (r *AgentRuntime) applyRuntimePolicy(policy policymodel.Policy) {
	r.tryApplyRuntimePolicy(policy)
}

func (r *AgentRuntime) tryApplyRuntimePolicy(policy policymodel.Policy) (detection.ApplyReport, bool) {
	policy = policymodel.Normalize(policy)
	engine, report := detection.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), r.detectionContentSnapshot(), r.detectionLimits())
	if report.Status == "rejected" {
		r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
		return report, false
	}
	r.setPolicy(policy)
	r.setDetection(engine)
	r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
	return report, true
}

func (r *AgentRuntime) rebuildDetection() detection.ApplyReport {
	policy := policymodel.Normalize(r.activePolicy())
	engine, report := detection.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), r.detectionContentSnapshot(), r.detectionLimits())
	if report.Status == "rejected" {
		r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
		return report
	}
	r.setDetection(engine)
	r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
	return report
}

func (r *AgentRuntime) buildDetectionWithSnapshot(snapshot agentcontent.Snapshot) (*detection.Engine, detection.ApplyReport) {
	policy := policymodel.Normalize(r.activePolicy())
	engine, report := detection.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), detectionContentSnapshotFromContent(snapshot), r.detectionLimits())
	return engine, report
}

func (r *AgentRuntime) setDetectionStatus(policy policymodel.Policy, report detection.ApplyReport, snapshot agentcontent.Snapshot) {
	status := agenthealth.DetectionHealth{
		PolicyID:               firstNonEmptyString(policy.Detection.PolicyID, policy.PolicyID),
		PolicyVersion:          policy.Detection.Version,
		FeatureFlags:           r.featureFlags,
		LastApplyStatus:        report.Status,
		UpdatedAt:              time.Now().UTC(),
		ContentRefs:            detectionContentRefs(snapshot),
		DefaultManifestVersion: snapshot.DefaultManifestVersion,
	}
	if report.Status == "rejected" {
		status.LastApplyError = strings.Join(report.Details, "; ")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detectionStatus = status
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (r *AgentRuntime) detectionLimits() detection.EngineLimits {
	return detection.EngineLimits{
		MaxCEPGroups: r.Config.Resource.MaxActiveCEPGroups,
		MaxCEPRefs:   r.Config.Resource.MaxEventRefsPerSignal,
	}
}

func samePolicyRuntime(a, b policymodel.Policy) bool {
	return a.PolicyID == b.PolicyID &&
		a.Version == b.Version &&
		a.Mode == b.Mode &&
		reflect.DeepEqual(a.Detection, b.Detection)
}
