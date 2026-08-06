package daemon

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func (s *policyController) applyCollectionPolicy(ctx context.Context, req *controlplanev1.ApplyPolicyRequest) *controlplanev1.ControlAck {
	s.runner.detectionUpdateMu.Lock()
	defer s.runner.detectionUpdateMu.Unlock()
	policy, err := agentpolicy.ParseCollectionPolicyJSON([]byte(req.GetPolicyJson()), s.runner.Config.Sensor.ObserveOnly)
	if err != nil {
		return rejectedAck(s.runner.Config, req.GetContext(), "collection", "invalid collection policy: "+err.Error())
	}
	reqScope := requestScope(req.GetContext())
	if policy.ScopeType == "" && reqScope.Type != "" {
		policy.ScopeType = reqScope.Type
		policy.ScopeSelector = reqScope.Selector
	}
	if policy.ScopeType == "" {
		if scope, err := s.runner.Config.Sensor.EffectiveScope(); err == nil {
			policy.ScopeType = scope.Type
			policy.ScopeSelector = scope.Selector
		}
	}
	policy, expansionReport, err := agentpolicy.ExpandCollectionPolicyRefs(policy, collectionContentSnapshot(s.runner.contentStore().Snapshot()))
	if err != nil {
		return rejectedAck(s.runner.Config, req.GetContext(), "collection", "resolve collection policy refs: "+err.Error())
	}
	intent, err := agentpolicy.CollectionPolicyIntent(policy)
	if err != nil {
		return rejectedAck(s.runner.Config, req.GetContext(), "collection", "compile collection policy: "+err.Error())
	}
	compileReport := tetragon.CompileReport(intent)
	compileReport.ResolvedRefs = expansionReport.ResolvedRefs
	if len(compileReport.UnsupportedSelectors) > 0 {
		return collectionAck(s.runner.Config, req.GetContext(), policy, "rejected", "collection policy contains unsupported selectors", false, compileReport, nil)
	}
	_, detectionReport := detection.NewWithRuntimeLimits(s.runner.activePolicy().Detection, s.runner.withCollectionCapabilities(intent), s.runner.detectionContentSnapshot(), s.runner.detectionLimits())
	if req.GetDryRun() {
		status := "validated"
		message := "collection policy accepted in dry-run"
		if detectionReport.Status == "degraded" {
			status = "degraded"
			message = "collection policy accepted in dry-run; detection dependencies degraded: " + strings.Join(detectionReport.Warnings, "; ")
		}
		return collectionAck(s.runner.Config, req.GetContext(), policy, status, message, false, compileReport, &detectionReport.Coverage)
	}
	if _, err := s.policyReconciler().Apply(ctx, intent); err != nil {
		return rejectedAck(s.runner.Config, req.GetContext(), "collection", "apply collection policy: "+err.Error())
	}
	if s.runner.localStore != nil {
		next := s.runner.currentEndpointPolicy()
		next.Collection = policy
		next.Version++
		if err := s.runner.persistEndpointPolicy(ctx, localstore.PolicySourceStandalone, next); err != nil {
			_, _ = s.policyReconciler().Apply(ctx, s.runner.currentCollectionIntent())
			return collectionAck(s.runner.Config, req.GetContext(), policy, "rejected", "persist collection policy: "+err.Error(), false, compileReport, nil)
		}
	}
	s.runner.setCollectionIntent(intent)
	active := policymodel.Normalize(s.runner.activePolicy())
	engine, report := detection.NewWithRuntimeLimits(active.Detection, intent, s.runner.detectionContentSnapshot(), s.runner.detectionLimits())
	s.runner.setDetection(engine)
	if report.Status == "degraded" {
		return collectionAck(s.runner.Config, req.GetContext(), policy, "degraded", "collection policy applied; detection dependencies degraded: "+strings.Join(report.Warnings, "; "), false, compileReport, &report.Coverage)
	}
	return collectionAck(s.runner.Config, req.GetContext(), policy, "applied", "collection policy applied", false, compileReport, &report.Coverage)
}

func (s *policyController) applyDetectionPolicy(ctx context.Context, req *controlplanev1.ApplyPolicyRequest) *controlplanev1.ControlAck {
	s.runner.detectionUpdateMu.Lock()
	defer s.runner.detectionUpdateMu.Unlock()
	var envelope struct {
		Detection *policymodel.DetectionPolicy `json:"detection"`
	}
	var next policymodel.DetectionPolicy
	if err := json.Unmarshal([]byte(req.GetPolicyJson()), &envelope); err == nil && envelope.Detection != nil {
		next = *envelope.Detection
	} else if err := json.Unmarshal([]byte(req.GetPolicyJson()), &next); err != nil {
		return rejectedAck(s.runner.Config, req.GetContext(), "detection", "invalid detection policy json: "+err.Error())
	}
	next = policymodel.NormalizeDetectionPolicy(next)
	engine, report := detection.NewWithRuntimeLimits(&next, s.runner.currentCollectionIntent(), s.runner.detectionContentSnapshot(), s.runner.detectionLimits())
	active := policymodel.Normalize(s.runner.activePolicy())
	active.Detection = &next
	if req.GetDryRun() {
		return detectionAck(s.runner.Config, req.GetContext(), active, report.Status, "detection policy accepted in dry-run: "+report.Message, false, report)
	}
	if report.Status == "rejected" {
		s.runner.setDetectionStatus(active, report, s.runner.contentStore().Snapshot())
		return detectionAck(s.runner.Config, req.GetContext(), active, "rejected", "detection policy rejected: "+strings.Join(report.Details, "; "), false, report)
	}
	if s.runner.localStore != nil {
		endpoint := s.runner.currentEndpointPolicy()
		endpoint.Detection = next
		endpoint.Version++
		if err := s.runner.persistEndpointPolicy(ctx, localstore.PolicySourceStandalone, endpoint); err != nil {
			return detectionAck(s.runner.Config, req.GetContext(), active, "rejected", "persist detection policy: "+err.Error(), false, report)
		}
	}
	s.runner.setPolicy(active)
	s.runner.setDetection(engine)
	s.runner.setDetectionStatus(active, report, s.runner.contentStore().Snapshot())
	return detectionAck(s.runner.Config, req.GetContext(), active, report.Status, report.Message, false, report)
}
