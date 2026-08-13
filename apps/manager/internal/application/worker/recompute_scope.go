package worker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	workerprocessing "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/worker/processing"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

const analysisWindow = 15 * time.Minute

type batchAnalysis struct {
	cloudSignals []ports.ObservedSignal
	incidents    []domaintelemetry.Incident
}

type labelSelector map[string]string

type analysisScope struct {
	labels labelSelector
	policy ports.DetectionPolicyRef
}

func (service *ProcessBatch) recomputeTouchedScopes(ctx context.Context, engine *workerprocessing.Engine, batch ports.DataBatch) (batchAnalysis, error) {
	result := batchAnalysis{}
	for _, scope := range touchedScopes(batch) {
		labels := scope.labels
		if scope.policy.ID == "" || scope.policy.Version == 0 {
			return result, fmt.Errorf("analysis scope requires policy_id and policy_version")
		}
		history, err := service.history.Read(ctx, batch.TenantID, labels, batch.CreatedAt.Add(-analysisWindow), batch.CreatedAt)
		if err != nil {
			return result, err
		}
		policy, err := service.policies.Published(ctx, batch.TenantID, scope.policy.ID, scope.policy.Version)
		if err != nil {
			return result, fmt.Errorf("read effective detection policy: %w", err)
		}
		events := mergeEvents(history.Events, matchingEvents(batch.Events, labels))
		signals := mergeSignals(history.Signals, matchingSignals(batch.Signals, labels))
		analysis := engine.AnalyzeWithPolicy(events, signalValues(signals), &policy)
		decorateIncidents(analysis.Incidents, batch, labels, events)
		result.cloudSignals = append(result.cloudSignals, observeCloudSignals(analysis.CloudSignals, signals, batch.CreatedAt)...)
		result.incidents = append(result.incidents, analysis.Incidents...)
	}
	return result, nil
}

func touchedScopes(batch ports.DataBatch) []analysisScope {
	unique := map[string]analysisScope{}
	for _, observed := range batch.Events {
		rememberScope(unique, observed.Event.Labels, observed.Policy)
	}
	for _, observed := range batch.Signals {
		rememberScope(unique, observed.Signal.Labels, observed.Policy)
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]analysisScope, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result
}

func rememberScope(scopes map[string]analysisScope, labels map[string]string, policy ports.DetectionPolicyRef) {
	selector := analysisSelector(labels)
	if len(selector) > 0 {
		scopes[labelSelectorKey(selector)] = analysisScope{labels: selector, policy: policy}
	}
}

func analysisSelector(labels map[string]string) labelSelector {
	selector := labelSelector{}
	for _, key := range []string{"case_type", "scenario", "workload", "policy_id", "policy_version"} {
		if value := strings.TrimSpace(labels[key]); value != "" {
			selector[key] = value
		}
	}
	return selector
}

func labelSelectorKey(labels labelSelector) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}

func mergeEvents(history, current []domaintelemetry.Event) []domaintelemetry.Event {
	byID := make(map[string]domaintelemetry.Event, len(history)+len(current))
	for _, event := range append(append([]domaintelemetry.Event{}, history...), current...) {
		if event.ID != "" {
			byID[event.ID] = event
		}
	}
	result := make([]domaintelemetry.Event, 0, len(byID))
	for _, event := range byID {
		result = append(result, event)
	}
	return result
}

func mergeSignals(history, current []ports.ObservedSignal) []ports.ObservedSignal {
	byID := make(map[string]ports.ObservedSignal, len(history)+len(current))
	for _, observed := range append(append([]ports.ObservedSignal{}, history...), current...) {
		if key := signalProjectionKey(observed.Signal); key != "" {
			byID[key] = observed
		}
	}
	result := make([]ports.ObservedSignal, 0, len(byID))
	for _, observed := range byID {
		result = append(result, observed)
	}
	return result
}

func signalValues(observed []ports.ObservedSignal) []domaintelemetry.Signal {
	result := make([]domaintelemetry.Signal, 0, len(observed))
	for _, item := range observed {
		result = append(result, item.Signal)
	}
	return result
}

func observeCloudSignals(signals []domaintelemetry.Signal, inputs []ports.ObservedSignal, fallback time.Time) []ports.ObservedSignal {
	observedAt := make(map[string]time.Time, len(inputs))
	for _, input := range inputs {
		observedAt[input.Signal.ID] = input.ObservedAt
	}
	result := make([]ports.ObservedSignal, 0, len(signals))
	for _, signal := range signals {
		var observed time.Time
		for _, ref := range signal.SignalRefs {
			if candidate := observedAt[ref]; !candidate.IsZero() && candidate.After(observed) {
				observed = candidate
			}
		}
		if observed.IsZero() {
			observed = fallback
		}
		result = append(result, ports.ObservedSignal{Signal: signal, ObservedAt: observed})
	}
	return result
}

func matchingEvents(events []ports.ObservedEvent, labels labelSelector) []domaintelemetry.Event {
	var result []domaintelemetry.Event
	for _, observed := range events {
		if labelsMatch(observed.Event.Labels, labels) {
			result = append(result, observed.Event)
		}
	}
	return result
}

func matchingSignals(signals []ports.ObservedSignal, labels labelSelector) []ports.ObservedSignal {
	var result []ports.ObservedSignal
	for _, observed := range signals {
		if observed.Signal.Where == domaintelemetry.SignalWhereEndpoint && labelsMatch(observed.Signal.Labels, labels) {
			result = append(result, observed)
		}
	}
	return result
}

func labelsMatch(values map[string]string, expected labelSelector) bool {
	for key, value := range expected {
		if values[key] != value {
			return false
		}
	}
	return true
}

func signalProjectionKey(signal domaintelemetry.Signal) string {
	if signal.ID != "" {
		return signal.ID
	}
	return strings.Join([]string{signal.Name, signal.LineageID, labelSelectorKey(analysisSelector(signal.Labels))}, "\x00")
}

func decorateIncidents(incidents []domaintelemetry.Incident, batch ports.DataBatch, labels labelSelector, events []domaintelemetry.Event) {
	first, last := incidentObservedRange(events)
	for index := range incidents {
		incidents[index].TenantID = batch.TenantID.String()
		incidents[index].CorrelationKey = labelSelectorKey(labels)
		incidents[index].AnalysisVersion = "incident.v1"
		incidents[index].FirstObservedAt = first
		incidents[index].LastObservedAt = last
	}
}

func incidentObservedRange(events []domaintelemetry.Event) (string, string) {
	var first, last uint64
	for _, event := range events {
		if event.OccurredAtNS == 0 {
			continue
		}
		if first == 0 || event.OccurredAtNS < first {
			first = event.OccurredAtNS
		}
		if event.OccurredAtNS > last {
			last = event.OccurredAtNS
		}
	}
	if first == 0 {
		return "", ""
	}
	return time.Unix(0, int64(first)).UTC().Format(time.RFC3339Nano), time.Unix(0, int64(last)).UTC().Format(time.RFC3339Nano)
}
