package store

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func (s *Store) AddEvent(ev *eventv1.CanonicalEvent) bool {
	if ev == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.GetId() != "" {
		for i, existing := range s.Events {
			if existing.GetTenantId() == ev.GetTenantId() && existing.GetId() == ev.GetId() {
				s.Events[i] = ev
				return false
			}
		}
	}
	s.Events = append(s.Events, ev)
	return true
}

func (s *Store) AddSignal(sig *signalv1.Signal) bool {
	if sig == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := signalKey(sig)
	for i, existing := range s.Signals {
		if key != "" && signalKey(existing) == key {
			s.Signals[i] = sig
			return false
		}
	}
	s.Signals = append(s.Signals, sig)
	return true
}

func (s *Store) AddIncident(inc *incidentv1.Incident) bool {
	if inc == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := incidentKey(inc)
	for i, existing := range s.Incidents {
		if key != "" && incidentKey(existing) == key {
			inc.Evidence = mergeEvidence(inc.GetEvidence(), existing.GetEvidence())
			s.Incidents[i] = inc
			return false
		}
	}
	s.Incidents = append(s.Incidents, inc)
	return true
}

func (s *Store) RecordDataBatchIngest(events, endpointSignals, cloudSignals, incidents int, convergenceLatency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recordMetrics(&s.Metrics, events, endpointSignals, cloudSignals, incidents, convergenceLatency)
}

// ListEvents reads from the in-process working set only. Telemetry is not
// persisted in the relational backend; durable event retention/search lives in
// the index tier (OpenSearch).
func (s *Store) ListEvents(labels LabelSelector, behavior string) []*eventv1.CanonicalEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*eventv1.CanonicalEvent, 0, len(s.Events))
	for _, ev := range s.Events {
		if !labelSelectorMatches(ev.GetLabels(), labels) {
			continue
		}
		if behavior != "" && ev.GetBehavior() != behavior {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// ListSignals reads from the in-process working set only. Like events, signals
// are telemetry and are not persisted in the relational backend; durable
// retention/search lives in the index tier (OpenSearch).
func (s *Store) ListSignals(labels LabelSelector, layer string, terminalOnly bool) []*signalv1.Signal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*signalv1.Signal, 0, len(s.Signals))
	for _, sig := range s.Signals {
		if !labelSelectorMatches(sig.GetLabels(), labels) {
			continue
		}
		if terminalOnly && !sig.GetTerminal() {
			continue
		}
		if layer != "" && layerName(sig.GetWhere()) != layer {
			continue
		}
		out = append(out, sig)
	}
	return out
}

func (s *Store) GetSignal(id string) (*signalv1.Signal, bool) {
	if id == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sig := range s.Signals {
		if sig.GetId() == id {
			return sig, true
		}
	}
	return nil, false
}

func (s *Store) ListIncidents(labels LabelSelector) []*incidentv1.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*incidentv1.Incident, 0, len(s.Incidents))
	for _, inc := range s.Incidents {
		if !labelSelectorMatches(inc.GetLabels(), labels) {
			continue
		}
		out = append(out, inc)
	}
	return out
}

func (s *Store) GetIncident(id string, labels LabelSelector) (*incidentv1.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inc := range s.Incidents {
		if id != "" && inc.GetId() != id {
			continue
		}
		if !labelSelectorMatches(inc.GetLabels(), labels) {
			continue
		}
		return inc, true
	}
	return nil, false
}

func (s *Store) AttachIncidentEvidence(id string, labels LabelSelector, evidence *incidentv1.EvidenceSubgraph) (*incidentv1.Incident, bool) {
	if (id == "" && len(labels) == 0) || evidence == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inc := range s.Incidents {
		if id != "" && inc.GetId() != id {
			continue
		}
		if !labelSelectorMatches(inc.GetLabels(), labels) {
			continue
		}
		inc.Evidence = mergeEvidence(inc.GetEvidence(), evidence)
		return inc, true
	}
	return nil, false
}

func (s *Store) MergeIncidents(targetID, sourceID string) (*incidentv1.Incident, bool) {
	if targetID == "" || sourceID == "" || targetID == sourceID {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var target *incidentv1.Incident
	var source *incidentv1.Incident
	sourceIndex := -1
	for i, inc := range s.Incidents {
		switch inc.GetId() {
		case targetID:
			target = inc
		case sourceID:
			source = inc
			sourceIndex = i
		}
	}
	if target == nil || source == nil {
		return nil, false
	}
	if source.GetSeverity() > target.GetSeverity() {
		target.Severity = source.GetSeverity()
	}
	target.Mitre = mergeStrings(target.GetMitre(), source.GetMitre())
	target.LineageIds = mergeStrings(target.GetLineageIds(), source.GetLineageIds())
	target.Terminals = mergeStrings(target.GetTerminals(), source.GetTerminals())
	target.Evidence = mergeEvidence(target.GetEvidence(), source.GetEvidence())
	target.ContributingSignals = mergeSignals(target.GetContributingSignals(), source.GetContributingSignals())
	s.Incidents = append(s.Incidents[:sourceIndex], s.Incidents[sourceIndex+1:]...)
	return target, true
}

func (s *Store) MetricsSnapshot() Metrics {
	s.mu.RLock()
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	s.mu.RUnlock()
	if metricsBackend, ok := backend.(MetricsBackend); ok {
		if metrics, err := metricsBackend.LoadMetrics(ctx); err == nil {
			return metrics
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Metrics
}

func (s *Store) SaveMetrics() error {
	s.mu.RLock()
	metrics := s.Metrics
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	s.mu.RUnlock()
	if metricsBackend, ok := backend.(MetricsBackend); ok {
		return metricsBackend.SaveMetrics(ctx, metrics)
	}
	return nil
}

func (s *Store) ResetMetrics() error {
	s.mu.Lock()
	s.Metrics = Metrics{}
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	s.mu.Unlock()
	if metricsBackend, ok := backend.(MetricsBackend); ok {
		return metricsBackend.ResetMetrics(ctx)
	}
	return nil
}

func (s *Store) DeleteByLabels(labels LabelSelector) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(labels) == 0 {
		s.Agents = nil
		s.Events = nil
		s.Signals = nil
		s.Incidents = nil
		s.Health = map[string]agenthealth.AgentHealth{}
		s.AgentSessions = nil
		s.Metrics = Metrics{}
		return
	}
	events := s.Events[:0]
	for _, ev := range s.Events {
		if !labelSelectorMatches(ev.GetLabels(), labels) {
			events = append(events, ev)
		}
	}
	s.Events = events
	signals := s.Signals[:0]
	for _, sig := range s.Signals {
		if !labelSelectorMatches(sig.GetLabels(), labels) {
			signals = append(signals, sig)
		}
	}
	s.Signals = signals
	incidents := s.Incidents[:0]
	for _, inc := range s.Incidents {
		if !labelSelectorMatches(inc.GetLabels(), labels) {
			incidents = append(incidents, inc)
		}
	}
	s.Incidents = incidents
}

func layerName(where signalv1.SignalWhere) string {
	switch where {
	case signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT:
		return "endpoint"
	case signalv1.SignalWhere_SIGNAL_WHERE_CLOUD:
		return "cloud"
	default:
		return ""
	}
}

func SignalLayerName(where signalv1.SignalWhere) string {
	return layerName(where)
}

func signalKey(sig *signalv1.Signal) string {
	if sig == nil {
		return ""
	}
	parts := []string{
		labelKey(sig.GetLabels()),
		layerName(sig.GetWhere()),
		sig.GetName(),
		sig.GetLineageId(),
		boolString(sig.GetTerminal()),
	}
	parts = append(parts, sortedStrings(sig.GetEventRefs())...)
	parts = append(parts, sortedStrings(sig.GetSignalRefs())...)
	for _, ent := range sortedEntities(sig.GetEntities()) {
		parts = append(parts, ent)
	}
	return stableKey(parts...)
}

func SignalProjectionKey(sig *signalv1.Signal) string {
	return signalKey(sig)
}

func incidentKey(inc *incidentv1.Incident) string {
	if inc == nil {
		return ""
	}
	parts := []string{
		inc.GetTenantId(),
		labelKey(inc.GetLabels()),
		inc.GetSummary(),
		inc.GetConverge().GetMethod(),
	}
	parts = append(parts, sortedStrings(inc.GetLineageIds())...)
	parts = append(parts, sortedStrings(inc.GetTerminals())...)
	for _, sig := range inc.GetContributingSignals() {
		parts = append(parts, signalKey(sig))
	}
	return stableKey(parts...)
}

func IncidentProjectionKey(inc *incidentv1.Incident) string {
	return incidentKey(inc)
}

func mergeEvidence(base, extra *incidentv1.EvidenceSubgraph) *incidentv1.EvidenceSubgraph {
	if base == nil && extra == nil {
		return nil
	}
	out := &incidentv1.EvidenceSubgraph{}
	seenNodes := map[string]bool{}
	seenEdges := map[string]bool{}
	appendNode := func(node *incidentv1.GraphNode) {
		if node == nil {
			return
		}
		key := graphNodeKey(node)
		if key == "" || seenNodes[key] {
			return
		}
		seenNodes[key] = true
		out.Nodes = append(out.Nodes, node)
	}
	appendEdge := func(edge *incidentv1.GraphEdge) {
		if edge == nil {
			return
		}
		key := graphEdgeKey(edge)
		if key == "" || seenEdges[key] {
			return
		}
		seenEdges[key] = true
		out.Edges = append(out.Edges, edge)
	}
	for _, node := range base.GetNodes() {
		appendNode(node)
	}
	for _, node := range extra.GetNodes() {
		appendNode(node)
	}
	for _, edge := range base.GetEdges() {
		appendEdge(edge)
	}
	for _, edge := range extra.GetEdges() {
		appendEdge(edge)
	}
	return out
}

func graphNodeKey(node *incidentv1.GraphNode) string {
	if node.GetId() != "" {
		return node.GetId()
	}
	return strings.Join([]string{node.GetKind(), node.GetLabel()}, "\x00")
}

func graphEdgeKey(edge *incidentv1.GraphEdge) string {
	if edge.GetId() != "" {
		return edge.GetId()
	}
	return strings.Join([]string{edge.GetFrom(), edge.GetTo(), edge.GetKind()}, "\x00")
}

func mergeStrings(base, extra []string) []string {
	out := append([]string(nil), base...)
	seen := map[string]bool{}
	for _, item := range out {
		seen[item] = true
	}
	for _, item := range extra {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func mergeSignals(base, extra []*signalv1.Signal) []*signalv1.Signal {
	out := append([]*signalv1.Signal(nil), base...)
	seen := map[string]bool{}
	for _, sig := range out {
		key := signalKey(sig)
		if key != "" {
			seen[key] = true
		}
	}
	for _, sig := range extra {
		key := signalKey(sig)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, sig)
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedEntities(in []*signalv1.EntityRef) []string {
	out := make([]string, 0, len(in))
	for _, ent := range in {
		out = append(out, strings.Join([]string{ent.GetKind(), ent.GetKey(), ent.GetRole()}, "\x00"))
	}
	sort.Strings(out)
	return out
}

func labelSelectorMatches(labels map[string]string, selector LabelSelector) bool {
	if len(selector) == 0 {
		return true
	}
	for key, want := range selector {
		if key == "" {
			continue
		}
		if labels[key] != want {
			return false
		}
	}
	return true
}

func labelKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, "\x00")
}

func stableKey(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}
