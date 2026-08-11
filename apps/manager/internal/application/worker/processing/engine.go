package processing

import (
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domainanalysis "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/analysis"
	domainrarity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type Engine struct{ analyzer *domainanalysis.Analyzer }

type AnalysisResult struct {
	CloudSignals []domaintelemetry.Signal
	Incidents    []domaintelemetry.Incident
}

func NewEngine() *Engine { return &Engine{analyzer: domainanalysis.NewAnalyzer()} }

func (engine *Engine) SetRarityBaseline(baseline domainrarity.Baseline) {
	if engine != nil && engine.analyzer != nil {
		engine.analyzer.SetRarityBaseline(baseline)
	}
}

func (engine *Engine) Analyze(events []domaintelemetry.Event, signals []domaintelemetry.Signal) AnalysisResult {
	return engine.AnalyzeWithPolicy(events, signals, nil)
}

func (engine *Engine) AnalyzeWithPolicy(events []domaintelemetry.Event, signals []domaintelemetry.Signal, policy *domaindetection.Policy) AnalysisResult {
	if engine == nil || engine.analyzer == nil {
		return AnalysisResult{}
	}
	result := engine.analyzer.Analyze(events, signals, policy)
	return AnalysisResult{CloudSignals: result.CloudSignals, Incidents: result.Incidents}
}
