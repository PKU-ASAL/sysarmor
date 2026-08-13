package analysis

import (
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/convergence"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/correlation"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/entity"
	incidentbuilder "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/incident"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	telemetryidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry/identity"
)

type Analyzer struct {
	incidents *incidentbuilder.Builder
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{incidents: incidentbuilder.NewBuilder()}
}

func (analyzer *Analyzer) SetRarityBaseline(baseline rarity.Baseline) {
	analyzer.incidents.Scorer = rarity.WorkloadBaselineScorer{Baseline: baseline.Snapshot()}
}

func (analyzer *Analyzer) Analyze(events []domaintelemetry.Event, signals []domaintelemetry.Signal, policy *detection.Policy) domaintelemetry.Analysis {
	view := correlation.Build(events, signals, policy)
	result := domaintelemetry.Analysis{}
	if cloudRuleEnabled(policy, "dropped_payload_executed_and_connects") && stagedPayloadDetected(view, policy) {
		signal := analyzer.cloudSignal("dropped_payload_executed_and_connects", view.Labels, 80,
			view.CollectEntities("payload_dropped", "reverse_shell_pattern", "suspicious_exec_connect"))
		signal.SignalRefs = view.CollectSignalRefs("payload_dropped", "reverse_shell_pattern", "suspicious_exec_connect")
		signal.CrossLineage = view.Has("suspicious_exec_connect") && !view.HasTerminal("reverse_shell_pattern")
		result.CloudSignals = append(result.CloudSignals, signal)
	}
	if cloudRuleEnabled(policy, "web_shell_chain") && view.Has("web_runtime_spawns_shell") && view.HasTerminal("reverse_shell_pattern") {
		result.CloudSignals = append(result.CloudSignals, analyzer.cloudSignal("web_shell_chain", view.Labels, 85,
			view.CollectEntities("web_runtime_spawns_shell", "reverse_shell_pattern")))
		result.CloudSignals[len(result.CloudSignals)-1].SignalRefs = view.CollectSignalRefs("web_runtime_spawns_shell", "reverse_shell_pattern")
	}
	allSignals := append(append([]domaintelemetry.Signal(nil), signals...), result.CloudSignals...)
	decision := convergence.Decide(view.ByName, result.CloudSignals, policy)
	if decision.Incident {
		result.Incidents = append(result.Incidents, analyzer.incidents.Build(allSignals, decision))
	}
	return result
}

func stagedPayloadDetected(view correlation.View, policy *detection.Policy) bool {
	if !view.Has("payload_dropped") {
		return false
	}
	return view.HasTerminal("reverse_shell_pattern") || crossLineageEnabled(policy) && view.Has("suspicious_exec_connect")
}

func crossLineageEnabled(policy *detection.Policy) bool {
	return policy == nil || policy.Converge == nil || policy.Converge.CrossLineage
}

func cloudRuleEnabled(policy *detection.Policy, name string) bool {
	if policy == nil || len(policy.CloudRules) == 0 {
		return true
	}
	for _, rule := range policy.CloudRules {
		if rule == name {
			return true
		}
	}
	return false
}

func (analyzer *Analyzer) cloudSignal(name string, labels map[string]string, risk uint32, entities []domaintelemetry.Entity) domaintelemetry.Signal {
	signal := domaintelemetry.Signal{
		Name: name, Where: domaintelemetry.SignalWhereCloud,
		BaseRisk: risk, LocalRarity: 1, GlobalRarity: 1, Entities: entity.Unique(entities), Labels: cloneLabels(labels),
	}
	signal.ID = "cloud-sig-" + telemetryidentity.DigestSignals([]domaintelemetry.Signal{signal}, nil)
	return signal
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
