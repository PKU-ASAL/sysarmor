package store

import (
	"strings"

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
			return false
		}
	}
	s.TenantSignals[tenantID] = append(s.TenantSignals[tenantID], signal)
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
	tenantSignals := s.TenantSignals[tenantID][:0]
	for _, signal := range s.TenantSignals[tenantID] {
		if labelSelectorMatches(signal.GetLabels(), labels) && layerName(signal.GetWhere()) == "cloud" {
			continue
		}
		tenantSignals = append(tenantSignals, signal)
	}
	s.TenantSignals[tenantID] = append(tenantSignals, cloudSignals...)
	s.replaceDerivedIncidents(tenantID, labels, incidents)
}

func (s *Store) replaceDerivedIncidents(tenantID string, labels LabelSelector, incidents []*incidentv1.Incident) {
	keptIncidents := s.Incidents[:0]
	for _, incident := range s.Incidents {
		if incident.GetTenantId() == tenantID && labelSelectorMatches(incident.GetLabels(), labels) {
			continue
		}
		keptIncidents = append(keptIncidents, incident)
	}
	s.Incidents = append(keptIncidents, incidents...)
}

func MergeMetrics(current, delta Metrics) Metrics {
	current.DataBatchesAppended += delta.DataBatchesAppended
	current.EventsIngested += delta.EventsIngested
	current.EndpointSignalsIngested += delta.EndpointSignalsIngested
	current.CloudSignalsEmitted += delta.CloudSignalsEmitted
	current.SignalsEmitted += delta.SignalsEmitted
	current.IncidentsCreated += delta.IncidentsCreated
	current.DroppedEvents += delta.DroppedEvents
	current.DuplicateEvents += delta.DuplicateEvents
	current.LastConvergenceLatencyMs = delta.LastConvergenceLatencyMs
	current.TotalConvergenceLatencyMs += delta.TotalConvergenceLatencyMs
	if delta.MaxConvergenceLatencyMs > current.MaxConvergenceLatencyMs {
		current.MaxConvergenceLatencyMs = delta.MaxConvergenceLatencyMs
	}
	if current.DataBatchesAppended > 0 {
		current.AverageConvergenceLatency = float64(current.TotalConvergenceLatencyMs) / float64(current.DataBatchesAppended)
	}
	return current
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
	s.mu.RLock()
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	metrics := s.MetricsByTenant[tenantID]
	s.mu.RUnlock()
	if tenantBackend, ok := backend.(TenantMetricsBackend); ok {
		if value, err := tenantBackend.LoadMetricsForTenant(ctx, tenantID); err == nil {
			return value
		}
	}
	return metrics
}
