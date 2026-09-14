package runtime

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (r *policyRuntime) withDetectionUpdateTransaction(fn func()) {
	r.detectionUpdateMu.Lock()
	defer r.detectionUpdateMu.Unlock()
	fn()
}

func (r *policyRuntime) beginLocalPolicyMutation(ctx context.Context, mutation bool) (func(), error) {
	if !mutation {
		return func() {}, nil
	}
	r.policyAuthorityMu.RLock()
	if r.management.localStore == nil {
		r.policyAuthorityMu.RUnlock()
		return nil, fmt.Errorf("local store is unavailable")
	}
	enrollment, err := r.management.localStore.Enrollment(ctx)
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

func (r *policyRuntime) activePolicy() policymodel.Policy {
	r.mu.RLock()
	policy := r.policy
	r.mu.RUnlock()
	if policy.PolicyID != "" {
		return policy
	}
	return policymodel.DefaultPolicy(r.management.currentIdentity().TenantID)
}

func (r *policyRuntime) setPolicy(policy policymodel.Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = policy
}

func (r *policyRuntime) currentDetection() *detectionruntime.State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.detection != nil {
		return r.detection
	}
	engine, _ := detectionadapter.NewWithRuntimeLimits(policymodel.DefaultDetectionPolicy(), r.collection, detectionruntime.ContentSnapshot{}, r.detectionLimits())
	return engine
}

func (r *policyRuntime) setDetection(engine *detectionruntime.State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detection = engine
}

func (r *policyRuntime) setCollectionIntent(intent contract.CollectionIntent) {
	intent = r.withCollectionCapabilities(intent)
	r.mu.Lock()
	r.collection = intent
	r.mu.Unlock()
}

func (r *policyRuntime) setSensorSupervisor(supervisor *sensorruntime.SubscriptionSupervisor) {
	r.sensor.mu.Lock()
	r.sensor.sensorSupervisor = supervisor
	r.sensor.mu.Unlock()
	r.mu.RLock()
	intent := r.collection
	r.mu.RUnlock()
	supervisor.UpdateIntent(intent)
}

func (r *sensorRuntime) currentSupervisor() *sensorruntime.SubscriptionSupervisor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sensorSupervisor
}

func (r *policyRuntime) currentCollectionIntent() contract.CollectionIntent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.collection
}

func (r *policyRuntime) withCollectionCapabilities(intent contract.CollectionIntent) contract.CollectionIntent {
	if len(intent.Capabilities) == 0 && len(r.sensor.capability.Collection) > 0 {
		intent.Capabilities = append([]contract.CollectionBehaviorCapability(nil), r.sensor.capability.Collection...)
	}
	return intent
}

func (r *policyRuntime) applyRuntimePolicy(policy policymodel.Policy) {
	r.tryApplyRuntimePolicy(policy)
}

func (r *policyRuntime) tryApplyRuntimePolicy(policy policymodel.Policy) (detectionruntime.ApplyReport, bool) {
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

func (r *policyRuntime) rebuildDetection() detectionruntime.ApplyReport {
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

func (r *policyRuntime) buildDetectionWithSnapshot(snapshot agentcontent.Snapshot) (*detectionruntime.State, detectionruntime.ApplyReport) {
	policy := policymodel.Normalize(r.activePolicy())
	engine, report := detectionadapter.NewWithRuntimeLimits(policy.Detection, r.currentCollectionIntent(), detectionContentSnapshotFromContent(snapshot), r.detectionLimits())
	return engine, report
}

func (r *policyRuntime) setDetectionStatus(policy policymodel.Policy, report detectionruntime.ApplyReport, snapshot agentcontent.Snapshot) {
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
	status.Learning = r.detectionStatus.Learning
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

func (r *policyRuntime) detectionLimits() detectionruntime.EngineLimits {
	return detectionruntime.EngineLimits{
		MaxCEPGroups: r.config.Resource.MaxActiveCEPGroups,
		MaxCEPRefs:   r.config.Resource.MaxEventRefsPerSignal,
	}
}

func samePolicyRuntime(a, b policymodel.Policy) bool {
	return a.PolicyID == b.PolicyID &&
		a.Version == b.Version &&
		a.Mode == b.Mode &&
		reflect.DeepEqual(a.Detection, b.Detection)
}
