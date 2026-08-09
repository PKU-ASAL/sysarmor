package managerapi

import (
	"fmt"
	"net/http"
	"strings"

	ingest "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	policyv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/policy/v1"
)

func (s *Server) recompute(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	effective, _, err := s.store.EffectivePolicyWithError(q.Get("tenant_id"), q.Get("agent_id"), q.Get("scope_type"), q.Get("scope_selector"))
	if err != nil {
		http.Error(w, fmt.Sprintf("read effective policy: %v", err), http.StatusInternalServerError)
		return
	}
	policy := effective.DetectionPolicy()
	if policy.Converge == nil {
		policy.Converge = &policyv1.ConvergeParams{CrossLineage: true}
	}
	switch q.Get("disable") {
	case "cloud.cross_lineage":
		policy.Converge.CrossLineage = false
	case "":
	default:
		if strings.HasPrefix(q.Get("disable"), "cloud.rule:") {
			disabled := strings.TrimPrefix(q.Get("disable"), "cloud.rule:")
			policy.CloudRules = removeString(policy.CloudRules, disabled)
			break
		}
		http.Error(w, fmt.Sprintf("unknown disable %q", q.Get("disable")), http.StatusBadRequest)
		return
	}
	switch q.Get("mode") {
	case "additive_threshold":
		policy.Converge.Mode = "additive_threshold"
		policy.Converge.AdditiveRiskThreshold = 100
	case "", "rarity_structural":
	default:
		http.Error(w, fmt.Sprintf("unknown converge mode %q", q.Get("mode")), http.StatusBadRequest)
		return
	}
	engine := ingest.NewEngine()
	tenantID := requestTenantID(r)
	request, err := s.identityRequest(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("resolve identity request: %v", err), http.StatusInternalServerError)
		return
	}
	baseline, err := s.identityQuery.Rarity(r.Context(), request)
	if err != nil {
		http.Error(w, fmt.Sprintf("read tenant rarity baseline: %v", err), http.StatusInternalServerError)
		return
	}
	engine.SetRarityBaseline(rarity.Baseline{WorkloadCounts: baseline.WorkloadCounts})
	result := engine.AnalyzeWithPolicy(nil, s.store.ListSignalsForTenant(tenantID, parseLabelSelector(q["label"]), "endpoint", false), policy)
	writeAnalysisResult(w, result)
}
