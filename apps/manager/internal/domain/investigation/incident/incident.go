package incident

import (
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/convergence"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/evidence"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	telemetryidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry/identity"
)

type Builder struct {
	Scorer rarity.Scorer
}

func NewBuilder() *Builder {
	return &Builder{Scorer: rarity.CountScorer{}}
}

func (builder *Builder) Build(events []domaintelemetry.Event, signals []domaintelemetry.Signal, decision convergence.Decision) domaintelemetry.Incident {
	scorer := builder.Scorer
	if scorer == nil {
		scorer = rarity.CountScorer{}
	}
	contributing := append([]domaintelemetry.Signal(nil), signals...)
	return domaintelemetry.Incident{
		ID:                  stableID(contributing, decision),
		Labels:              commonLabels(contributing),
		Summary:             "SysArmor detected a causal attack chain",
		Severity:            80,
		LineageIDs:          lineageIDs(contributing),
		ConclusionEntities:  conclusionEntities(contributing),
		Evidence:            evidenceSubgraph(events, contributing),
		Converge:            &domaintelemetry.ConvergeTrace{Method: decision.Method, Score: scorer.Score(contributing), Controls: append([]string(nil), decision.Controls...)},
		ContributingSignals: contributing,
	}
}

func evidenceSubgraph(events []domaintelemetry.Event, signals []domaintelemetry.Signal) *domaintelemetry.EvidenceSubgraph {
	value := evidence.FromEvents(events, signals)
	return &value
}

func stableID(signals []domaintelemetry.Signal, decision convergence.Decision) string {
	context := []string{"method:" + decision.Method}
	for _, control := range decision.Controls {
		context = append(context, "control:"+control)
	}
	return "inc-" + telemetryidentity.DigestSignals(signals, context)
}

func lineageIDs(signals []domaintelemetry.Signal) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, signal := range signals {
		if signal.LineageID == "" {
			continue
		}
		if _, exists := seen[signal.LineageID]; !exists {
			seen[signal.LineageID] = struct{}{}
			result = append(result, signal.LineageID)
		}
	}
	return result
}

func commonLabels(signals []domaintelemetry.Signal) map[string]string {
	if len(signals) == 0 {
		return nil
	}
	common := cloneLabels(signals[0].Labels)
	for _, signal := range signals[1:] {
		for key, value := range common {
			if signal.Labels[key] != value {
				delete(common, key)
			}
		}
	}
	return common
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

func conclusionEntities(signals []domaintelemetry.Signal) []string {
	var result []string
	for _, signal := range signals {
		if signal.Stage != domaintelemetry.SignalStageConclusion {
			continue
		}
		for _, current := range signal.Entities {
			if current.Kind == "process" {
				result = append(result, current.Key)
			}
		}
	}
	return result
}
