package store

import (
	"strings"
	"time"

	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func (s *Store) AddSignalForTenant(tenantID string, signal *signalv1.Signal) bool {
	if strings.TrimSpace(tenantID) == "" || signal == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TenantSignals == nil {
		s.TenantSignals = map[string][]*signalv1.Signal{}
	}
	key := signalKey(signal)
	for i, existing := range s.TenantSignals[tenantID] {
		if key != "" && signalKey(existing) == key {
			s.TenantSignals[tenantID][i] = signal
			for globalIndex, globalSignal := range s.Signals {
				if globalSignal == existing {
					s.Signals[globalIndex] = signal
					break
				}
			}
			return false
		}
	}
	s.TenantSignals[tenantID] = append(s.TenantSignals[tenantID], signal)
	s.Signals = append(s.Signals, signal)
	return true
}

func (s *Store) GetSignalForTenant(tenantID, id string) (*signalv1.Signal, bool) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(id) == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, signal := range s.TenantSignals[tenantID] {
		if signal.GetId() == id {
			return signal, true
		}
	}
	return nil, false
}

func (s *Store) ReplaceDerivedForLabels(tenantID string, labels LabelSelector, cloudSignals []*signalv1.Signal, incidents []*incidentv1.Incident) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TenantSignals == nil {
		s.TenantSignals = map[string][]*signalv1.Signal{}
	}
	ownedSignals := make(map[*signalv1.Signal]struct{}, len(s.TenantSignals[tenantID]))
	for _, signal := range s.TenantSignals[tenantID] {
		ownedSignals[signal] = struct{}{}
	}
	tenantSignals := s.TenantSignals[tenantID][:0]
	for _, signal := range s.TenantSignals[tenantID] {
		if labelSelectorMatches(signal.GetLabels(), labels) && layerName(signal.GetWhere()) == "cloud" {
			continue
		}
		tenantSignals = append(tenantSignals, signal)
	}
	s.TenantSignals[tenantID] = append(tenantSignals, cloudSignals...)
	s.replaceGlobalDerived(tenantID, labels, ownedSignals, cloudSignals, incidents)
}

func (s *Store) replaceGlobalDerived(tenantID string, labels LabelSelector, owned map[*signalv1.Signal]struct{}, cloudSignals []*signalv1.Signal, incidents []*incidentv1.Incident) {
	signals := s.Signals[:0]
	for _, signal := range s.Signals {
		_, belongsToTenant := owned[signal]
		if belongsToTenant && labelSelectorMatches(signal.GetLabels(), labels) && layerName(signal.GetWhere()) == "cloud" {
			continue
		}
		signals = append(signals, signal)
	}
	s.Signals = append(signals, cloudSignals...)
	keptIncidents := s.Incidents[:0]
	for _, incident := range s.Incidents {
		if incident.GetTenantId() == tenantID && labelSelectorMatches(incident.GetLabels(), labels) {
			continue
		}
		keptIncidents = append(keptIncidents, incident)
	}
	s.Incidents = append(keptIncidents, incidents...)
}

func (s *Store) RecordDataBatchIngestForTenant(tenantID string, events, endpointSignals, cloudSignals, incidents int, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MetricsByTenant == nil {
		s.MetricsByTenant = map[string]Metrics{}
	}
	metrics := s.MetricsByTenant[tenantID]
	recordMetrics(&metrics, events, endpointSignals, cloudSignals, incidents, latency)
	s.MetricsByTenant[tenantID] = metrics
	recordMetrics(&s.Metrics, events, endpointSignals, cloudSignals, incidents, latency)
}

func recordMetrics(metrics *Metrics, events, endpointSignals, cloudSignals, incidents int, latency time.Duration) {
	latencyMs := uint64(latency.Milliseconds())
	metrics.DataBatchesAppended++
	metrics.EventsIngested += uint64(events)
	metrics.EndpointSignalsIngested += uint64(endpointSignals)
	metrics.CloudSignalsEmitted += uint64(cloudSignals)
	metrics.SignalsEmitted += uint64(endpointSignals + cloudSignals)
	metrics.IncidentsCreated += uint64(incidents)
	metrics.LastConvergenceLatencyMs = latencyMs
	metrics.TotalConvergenceLatencyMs += latencyMs
	if latencyMs > metrics.MaxConvergenceLatencyMs {
		metrics.MaxConvergenceLatencyMs = latencyMs
	}
	metrics.AverageConvergenceLatency = float64(metrics.TotalConvergenceLatencyMs) / float64(metrics.DataBatchesAppended)
}

func (s *Store) ListEventsForTenant(tenantID string, labels LabelSelector, behavior string) []*eventv1.CanonicalEvent {
	events := s.ListEvents(labels, behavior)
	out := events[:0]
	for _, event := range events {
		if event.GetTenantId() == tenantID {
			out = append(out, event)
		}
	}
	return out
}

func (s *Store) ListSignalsForTenant(tenantID string, labels LabelSelector, layer string, terminalOnly bool) []*signalv1.Signal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*signalv1.Signal, 0, len(s.TenantSignals[tenantID]))
	for _, signal := range s.TenantSignals[tenantID] {
		if !labelSelectorMatches(signal.GetLabels(), labels) || terminalOnly && !signal.GetTerminal() {
			continue
		}
		if layer == "" || layerName(signal.GetWhere()) == layer {
			out = append(out, signal)
		}
	}
	return out
}

func (s *Store) ListIncidentsForTenant(tenantID string, labels LabelSelector) []*incidentv1.Incident {
	incidents := s.ListIncidents(labels)
	out := incidents[:0]
	for _, incident := range incidents {
		if incident.GetTenantId() == tenantID {
			out = append(out, incident)
		}
	}
	return out
}

func (s *Store) MetricsSnapshotForTenant(tenantID string) Metrics {
	metrics, _ := s.MetricsSnapshotForTenantWithError(tenantID)
	return metrics
}

func (s *Store) MetricsSnapshotForTenantWithError(tenantID string) (Metrics, error) {
	s.mu.RLock()
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	metrics := s.MetricsByTenant[tenantID]
	s.mu.RUnlock()
	if tenantBackend, ok := backend.(TenantMetricsBackend); ok {
		return tenantBackend.LoadMetricsForTenant(ctx, tenantID)
	}
	return metrics, nil
}
