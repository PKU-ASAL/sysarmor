package runtime

import (
	"reflect"
	"strings"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (r *Coordinator) activePolicy() policymodel.Policy {
	r.policyRuntime.mu.RLock()
	policy := r.policy
	r.policyRuntime.mu.RUnlock()
	if policy.PolicyID != "" {
		return policy
	}
	return policymodel.DefaultPolicy(r.currentIdentity().TenantID)
}

func (r *Coordinator) setPolicy(policy policymodel.Policy) {
	r.policyRuntime.mu.Lock()
	defer r.policyRuntime.mu.Unlock()
	r.policy = policy
}

func (r *Coordinator) currentDetection() *detectionruntime.State {
	r.policyRuntime.mu.RLock()
	defer r.policyRuntime.mu.RUnlock()
	if r.detection != nil {
		return r.detection
	}
	engine, _ := detectionadapter.NewWithRuntimeLimits(policymodel.DefaultDetectionPolicy(), r.collection, detectionruntime.ContentSnapshot{}, r.detectionLimits())
	return engine
}

func (r *Coordinator) setDetection(engine *detectionruntime.State) {
	r.policyRuntime.mu.Lock()
	defer r.policyRuntime.mu.Unlock()
	r.detection = engine
}

func (r *Coordinator) setCollectionIntent(intent contract.CollectionIntent) {
	intent = r.withCollectionCapabilities(intent)
	r.policyRuntime.mu.Lock()
	r.collection = intent
	r.policyRuntime.mu.Unlock()
}

func (r *Coordinator) setSensorSupervisor(supervisor *sensorruntime.SubscriptionSupervisor) {
	r.sensorRuntime.mu.Lock()
	r.sensorSupervisor = supervisor
	r.sensorRuntime.mu.Unlock()
	r.policyRuntime.mu.RLock()
	intent := r.collection
	r.policyRuntime.mu.RUnlock()
	supervisor.UpdateIntent(intent)
}

func (r *Coordinator) currentCollectionIntent() contract.CollectionIntent {
	r.policyRuntime.mu.RLock()
	defer r.policyRuntime.mu.RUnlock()
	return r.collection
}

func (r *Coordinator) withCollectionCapabilities(intent contract.CollectionIntent) contract.CollectionIntent {
	if len(intent.Capabilities) == 0 && len(r.capability.Collection) > 0 {
		intent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), r.capability.Collection...)
	}
	return intent
}

func (r *Coordinator) applyRuntimePolicy(policy policymodel.Policy) {
	r.tryApplyRuntimePolicy(policy)
}

func (r *Coordinator) tryApplyRuntimePolicy(policy policymodel.Policy) (detectionruntime.ApplyReport, bool) {
	policy = policymodel.Normalize(policy)
	engine, report := detectionadapter.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), r.detectionContentSnapshot(), r.detectionLimits())
	if report.Status == "rejected" {
		r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
		return report, false
	}
	r.setPolicy(policy)
	r.setDetection(engine)
	r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
	return report, true
}

func (r *Coordinator) rebuildDetection() detectionruntime.ApplyReport {
	policy := policymodel.Normalize(r.activePolicy())
	engine, report := detectionadapter.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), r.detectionContentSnapshot(), r.detectionLimits())
	if report.Status == "rejected" {
		r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
		return report
	}
	r.setDetection(engine)
	r.setDetectionStatus(policy, report, r.contentStore().Snapshot())
	return report
}

func (r *Coordinator) buildDetectionWithSnapshot(snapshot agentcontent.Snapshot) (*detectionruntime.State, detectionruntime.ApplyReport) {
	policy := policymodel.Normalize(r.activePolicy())
	engine, report := detectionadapter.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), detectionContentSnapshotFromContent(snapshot), r.detectionLimits())
	return engine, report
}

func (r *Coordinator) setDetectionStatus(policy policymodel.Policy, report detectionruntime.ApplyReport, snapshot agentcontent.Snapshot) {
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
	r.policyRuntime.mu.Lock()
	defer r.policyRuntime.mu.Unlock()
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

func (r *Coordinator) detectionLimits() detectionruntime.EngineLimits {
	return detectionruntime.EngineLimits{
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
