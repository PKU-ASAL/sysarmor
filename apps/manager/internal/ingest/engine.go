package ingestworker

import (
	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainanalysis "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/analysis"
	domainrarity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	policyv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/policy/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type Engine struct{ analyzer *domainanalysis.Analyzer }

type AnalysisResult struct {
	CloudSignals []*signalv1.Signal
	Incidents    []*incidentv1.Incident
}

func NewEngine() *Engine { return &Engine{analyzer: domainanalysis.NewAnalyzer()} }

func (engine *Engine) SetRarityBaseline(baseline domainrarity.Baseline) {
	if engine != nil && engine.analyzer != nil {
		engine.analyzer.SetRarityBaseline(baseline)
	}
}

func (engine *Engine) Analyze(events []*eventv1.CanonicalEvent, signals []*signalv1.Signal) AnalysisResult {
	return engine.AnalyzeWithPolicy(events, signals, nil)
}

func (engine *Engine) AnalyzeWithPolicy(events []*eventv1.CanonicalEvent, signals []*signalv1.Signal, policy *policyv1.DetectionPolicy) AnalysisResult {
	if engine == nil || engine.analyzer == nil {
		return AnalysisResult{}
	}
	domainEvents := make([]domaintelemetry.Event, 0, len(events))
	for _, value := range events {
		mapped, err := contractmapper.EventToDomain(value)
		if err == nil {
			domainEvents = append(domainEvents, mapped)
		}
	}
	domainSignals := make([]domaintelemetry.Signal, 0, len(signals))
	for _, value := range signals {
		mapped, err := contractmapper.SignalToDomain(value)
		if err == nil {
			domainSignals = append(domainSignals, mapped)
		}
	}
	result := engine.analyzer.Analyze(domainEvents, domainSignals, policyToDomain(policy))
	converted := AnalysisResult{}
	for _, value := range result.CloudSignals {
		converted.CloudSignals = append(converted.CloudSignals, contractmapper.SignalFromDomain(value))
	}
	for _, value := range result.Incidents {
		converted.Incidents = append(converted.Incidents, contractmapper.IncidentFromDomain(value))
	}
	return converted
}

func policyToDomain(value *policyv1.DetectionPolicy) *domaindetection.Policy {
	if value == nil {
		return nil
	}
	result := &domaindetection.Policy{EndpointRules: append([]string(nil), value.GetEndpointRules()...), CloudRules: append([]string(nil), value.GetCloudRules()...)}
	if converge := value.GetConverge(); converge != nil {
		result.Converge = &domaindetection.ConvergePolicy{Mode: converge.GetMode(), CrossLineage: converge.GetCrossLineage(), AdditiveRiskThreshold: converge.GetAdditiveRiskThreshold()}
	}
	return result
}
