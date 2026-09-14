package rarity

import (
	"strings"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Scorer interface {
	Score([]domaintelemetry.Signal) float32
}

type Baseline struct {
	WorkloadCounts map[string]map[string]uint64
}

type RiskScorer struct{}

func (RiskScorer) Score(signals []domaintelemetry.Signal) float32 {
	var score float32
	for _, signal := range signals {
		score += float32(signal.BaseRisk) * signalRarity(signal)
	}
	return score
}

type CountScorer struct{}

func (CountScorer) Score(signals []domaintelemetry.Signal) float32 {
	counts := make(map[string]uint32)
	var score float32
	for _, signal := range signals {
		key := signalKey(signal)
		counts[key]++
		score += float32(signal.BaseRisk) * signalRarity(signal) / float32(counts[key])
	}
	return score
}

type WorkloadBaselineScorer struct {
	Baseline Baseline
}

func (scorer WorkloadBaselineScorer) Score(signals []domaintelemetry.Signal) float32 {
	var score float32
	for _, signal := range signals {
		score += float32(signal.BaseRisk) * signalRarity(signal) * scorer.workloadRarity(signal)
	}
	return score
}

func (scorer WorkloadBaselineScorer) workloadRarity(signal domaintelemetry.Signal) float32 {
	count := scorer.Baseline.Count(workloadKey(signal), signalKey(signal))
	if count == 0 {
		return 1
	}
	return 1 / float32(count+1)
}

func (baseline Baseline) Count(workload, signal string) uint64 {
	if signals := baseline.WorkloadCounts[workload]; signals != nil && signals[signal] > 0 {
		return signals[signal]
	}
	return baseline.WorkloadCounts["global"][signal]
}

func (baseline *Baseline) Observe(signals []domaintelemetry.Signal) {
	for _, value := range signals {
		signal := signalKey(value)
		if signal == "" {
			continue
		}
		workload := workloadKey(value)
		baseline.Add(workload, signal, 1)
		if workload != "global" {
			baseline.Add("global", signal, 1)
		}
	}
}

func (baseline *Baseline) Add(workload, signal string, count uint64) {
	workload, signal = strings.TrimSpace(workload), strings.TrimSpace(signal)
	if workload == "" {
		workload = "global"
	}
	if signal == "" || count == 0 {
		return
	}
	if baseline.WorkloadCounts == nil {
		baseline.WorkloadCounts = make(map[string]map[string]uint64)
	}
	if baseline.WorkloadCounts[workload] == nil {
		baseline.WorkloadCounts[workload] = make(map[string]uint64)
	}
	baseline.WorkloadCounts[workload][signal] += count
}

func (baseline *Baseline) Merge(other Baseline) {
	for workload, signals := range other.WorkloadCounts {
		for signal, count := range signals {
			baseline.Add(workload, signal, count)
		}
	}
}

func (baseline Baseline) Snapshot() Baseline {
	result := Baseline{WorkloadCounts: make(map[string]map[string]uint64, len(baseline.WorkloadCounts))}
	for workload, signals := range baseline.WorkloadCounts {
		result.WorkloadCounts[workload] = make(map[string]uint64, len(signals))
		for signal, count := range signals {
			result.WorkloadCounts[workload][signal] = count
		}
	}
	return result
}

func signalRarity(signal domaintelemetry.Signal) float32 {
	if signal.GlobalRarity == 0 {
		return 1
	}
	return signal.GlobalRarity
}

func signalKey(signal domaintelemetry.Signal) string {
	if key := strings.TrimSpace(signal.Name); key != "" {
		return key
	}
	return strings.TrimSpace(signal.ID)
}

func workloadKey(signal domaintelemetry.Signal) string {
	for _, kind := range []string{"pod", "container", "host", "user"} {
		for _, value := range signal.Entities {
			if value.Kind == kind && value.Key != "" {
				return kind + ":" + strings.TrimPrefix(value.Key, kind+":")
			}
		}
	}
	if signal.Labels["workload"] != "" {
		return "workload:" + signal.Labels["workload"]
	}
	if signal.Labels["scenario"] != "" {
		return "scenario:" + signal.Labels["scenario"]
	}
	return "global"
}
