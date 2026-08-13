package convergence

import (
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Decision struct {
	Incident bool
	Method   string
	Controls []string
}

func Decide(byName map[string][]domaintelemetry.Signal, cloud []domaintelemetry.Signal, policy *detection.Policy) Decision {
	if additivePolicy(policy) {
		threshold := policy.Converge.AdditiveRiskThreshold
		if threshold == 0 {
			threshold = 100
		}
		return Decision{Incident: additiveRisk(byName) >= threshold, Method: "additive_threshold", Controls: []string{"additive_threshold"}}
	}
	if hasTerminal(byName["reverse_shell_pattern"]) {
		return Decision{Incident: true, Method: "rarity+causal-topk", Controls: []string{"terminal_reverse_shell"}}
	}
	if crossLineageEnabled(policy) && hasCrossLineageSignal(cloud) {
		return Decision{Incident: true, Method: "rarity+causal-topk", Controls: []string{"cross_lineage_payload_connect"}}
	}
	return Decision{Method: "rarity+causal-topk"}
}

func additivePolicy(policy *detection.Policy) bool {
	return policy != nil && policy.Converge != nil && policy.Converge.Mode == "additive_threshold"
}

func crossLineageEnabled(policy *detection.Policy) bool {
	return policy == nil || policy.Converge == nil || policy.Converge.CrossLineage
}

func hasTerminal(signals []domaintelemetry.Signal) bool {
	for _, signal := range signals {
		if signal.Terminal {
			return true
		}
	}
	return false
}

func hasCrossLineageSignal(signals []domaintelemetry.Signal) bool {
	for _, signal := range signals {
		if signal.Name == "dropped_payload_executed_and_connects" && signal.CrossLineage {
			return true
		}
	}
	return false
}

func additiveRisk(byName map[string][]domaintelemetry.Signal) uint32 {
	var total uint32
	for _, signals := range byName {
		for _, signal := range signals {
			total += signal.BaseRisk
		}
	}
	return total
}
