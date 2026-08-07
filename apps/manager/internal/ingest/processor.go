package ingestworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	analyticingest "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/ingest"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	policyv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/policy/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Processor struct {
	store     *store.Store
	engine    *analyticingest.Engine
	projector platformopensearch.Projector
	history   HistoryReader
	local     bool
}

type Result struct {
	AcceptedEvents  int
	AcceptedSignals int
	CloudSignals    int
	Incidents       int
}

func NewProcessor(st *store.Store, projector platformopensearch.Projector) *Processor {
	if projector == nil {
		projector = platformopensearch.NoopIndexer{}
	}
	return &Processor{store: st, engine: analyticingest.NewEngine(), projector: projector, history: storeHistory{store: st}, local: true}
}

func NewProcessorWithHistory(st *store.Store, projector platformopensearch.Projector, history HistoryReader) *Processor {
	if projector == nil {
		projector = platformopensearch.NoopIndexer{}
	}
	return &Processor{store: st, engine: analyticingest.NewEngine(), projector: projector, history: history}
}

func (p *Processor) Process(ctx context.Context, batch *dataplanev1.DataBatch) (Result, error) {
	if p == nil || p.store == nil {
		return Result{}, fmt.Errorf("ingest processor store is nil")
	}
	if batch == nil || batch.GetHeader() == nil {
		return Result{}, fmt.Errorf("data batch header identity is required")
	}
	agent := store.AgentIdentityFromDataBatch(batch)
	tenantID := agent.Normalized().TenantID
	p.store.AddAgent(agent)
	touchedScopes := map[string]touchedScope{}
	currentEvents := make([]*eventv1.CanonicalEvent, 0, len(batch.GetEvents()))
	currentSignals := make([]*signalv1.Signal, 0, len(batch.GetSignals()))
	for _, frame := range batch.GetEvents() {
		ev := frame.GetEvent()
		if ev == nil {
			continue
		}
		if ev.GetTenantId() != "" && ev.GetTenantId() != tenantID {
			return Result{}, fmt.Errorf("event tenant_id does not match batch identity")
		}
		ev.TenantId = tenantID
		currentEvents = append(currentEvents, ev)
		rememberTouchedScope(touchedScopes, ev.GetLabels(), agent)
		if p.local {
			p.store.AddEvent(ev)
		}
	}
	for _, frame := range batch.GetSignals() {
		sig := frame.GetSignal()
		currentSignals = append(currentSignals, sig)
		rememberTouchedScope(touchedScopes, sig.GetLabels(), agent)
		if p.local {
			p.store.AddSignalForTenant(tenantID, sig)
		}
	}
	start := time.Now()
	if p.local {
		p.engine.SetRarityBaseline(p.store.RarityBaselineSnapshotForTenant(tenantID))
	}
	upper := batchUpperTime(batch, start)
	cloudSignals, incidents, derivedDocs, err := p.recomputeTouchedScopes(ctx, touchedScopes, currentEvents, currentSignals, upper)
	if err != nil {
		return Result{}, err
	}
	docs, err := batchDocuments(batch, upper)
	if err != nil {
		return Result{}, err
	}
	docs = append(docs, derivedDocs...)
	if err := p.projector.BulkIndex(ctx, docs); err != nil {
		return Result{}, err
	}
	convergenceLatency := time.Since(start)
	p.store.RecordDataBatchIngestForTenant(tenantID, len(currentEvents), len(currentSignals), cloudSignals, incidents, convergenceLatency)
	if p.local {
		p.store.ObserveRaritySignalsForTenant(tenantID, currentSignals)
	}
	if err := p.store.Save(); err != nil {
		return Result{}, err
	}
	if err := p.store.SaveMetrics(); err != nil {
		return Result{}, err
	}
	return Result{AcceptedEvents: len(currentEvents), AcceptedSignals: len(currentSignals), CloudSignals: cloudSignals, Incidents: incidents}, nil
}

type touchedScope struct {
	labels store.LabelSelector
	agent  store.AgentIdentity
}

func rememberTouchedScope(scopes map[string]touchedScope, labels map[string]string, agent store.AgentIdentity) {
	selector := analysisSelector(labels)
	if len(selector) == 0 {
		return
	}
	scopes[labelSelectorKey(selector)] = touchedScope{labels: selector, agent: agent}
}

func analysisSelector(labels map[string]string) store.LabelSelector {
	selector := store.LabelSelector{}
	for _, key := range []string{"case_type", "scenario", "workload"} {
		if value := strings.TrimSpace(labels[key]); value != "" {
			selector[key] = value
		}
	}
	return selector
}

func labelSelectorKey(labels store.LabelSelector) string {
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

func (p *Processor) recomputeTouchedScopes(ctx context.Context, touchedScopes map[string]touchedScope, currentEvents []*eventv1.CanonicalEvent, currentSignals []*signalv1.Signal, upper time.Time) (int, int, []platformopensearch.Document, error) {
	totalCloud := 0
	totalIncidents := 0
	var documents []platformopensearch.Document
	for _, scope := range touchedScopes {
		historyEvents, historySignals, err := p.history.Read(ctx, scope.agent.Normalized().TenantID, scope.labels, upper.Add(-15*time.Minute), upper)
		if err != nil {
			return 0, 0, nil, err
		}
		events := mergeEvents(historyEvents, matchingEvents(currentEvents, scope.labels))
		endpointSignals := mergeSignals(historySignals, matchingSignals(currentSignals, scope.labels))
		policy := p.effectiveDetectionPolicyForAgent(scope.agent)
		analysis := p.engine.AnalyzeWithPolicy(events, endpointSignals, policy)
		firstObserved, lastObserved := incidentObservedRange(events)
		for _, inc := range analysis.Incidents {
			inc.TenantId = scope.agent.Normalized().TenantID
			inc.CorrelationKey = labelSelectorKey(scope.labels)
			inc.AnalysisVersion = "incident.v1"
			inc.FirstObservedAt = firstObserved
			inc.LastObservedAt = lastObserved
		}
		if p.local {
			localIncidents := make([]*incidentv1.Incident, 0, len(analysis.Incidents))
			for _, incident := range analysis.Incidents {
				localIncidents = append(localIncidents, proto.Clone(incident).(*incidentv1.Incident))
			}
			p.store.ReplaceDerivedForLabels(scope.agent.Normalized().TenantID, scope.labels, analysis.CloudSignals, localIncidents)
		}
		for _, sig := range analysis.CloudSignals {
			doc, err := signalDocument(sig)
			if err != nil {
				return 0, 0, nil, err
			}
			documents = append(documents, decorateDocument(doc, scope.agent.Normalized().TenantID, upper))
		}
		for _, inc := range analysis.Incidents {
			docs, err := incidentDocuments(inc)
			if err != nil {
				return 0, 0, nil, err
			}
			for _, doc := range docs {
				documents = append(documents, decorateDocument(doc, scope.agent.Normalized().TenantID, upper))
			}
		}
		totalCloud += len(analysis.CloudSignals)
		totalIncidents += len(analysis.Incidents)
	}
	return totalCloud, totalIncidents, documents, nil
}

func incidentObservedRange(events []*eventv1.CanonicalEvent) (string, string) {
	var first, last uint64
	for _, event := range events {
		observed := event.GetOccurredAtNs()
		if observed == 0 {
			continue
		}
		if first == 0 || observed < first {
			first = observed
		}
		if observed > last {
			last = observed
		}
	}
	if first == 0 {
		return "", ""
	}
	return time.Unix(0, int64(first)).UTC().Format(time.RFC3339Nano), time.Unix(0, int64(last)).UTC().Format(time.RFC3339Nano)
}

func batchUpperTime(batch *dataplanev1.DataBatch, fallback time.Time) time.Time {
	if created := batch.GetHeader().GetCreatedAtUnixNano(); created > 0 {
		return time.Unix(0, created).UTC()
	}
	var latest uint64
	for _, frame := range batch.GetEvents() {
		if frame.GetEvent().GetOccurredAtNs() > latest {
			latest = frame.GetEvent().GetOccurredAtNs()
		}
	}
	if latest > 0 {
		return time.Unix(0, int64(latest)).UTC()
	}
	return fallback.UTC()
}

func frameTime(raw string, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC()
	}
	return fallback.UTC()
}

func decorateDocument(doc platformopensearch.Document, tenantID string, observed time.Time) platformopensearch.Document {
	var body map[string]any
	if json.Unmarshal(doc.Body, &body) != nil {
		return doc
	}
	delete(body, "tenantId")
	body["tenant_id"] = tenantID
	body["@timestamp"] = observed.UTC().Format(time.RFC3339Nano)
	doc.Body, _ = json.Marshal(body)
	return doc
}

func matchingEvents(events []*eventv1.CanonicalEvent, labels store.LabelSelector) []*eventv1.CanonicalEvent {
	var out []*eventv1.CanonicalEvent
	for _, event := range events {
		if store.LabelsMatch(event.GetLabels(), labels) {
			out = append(out, event)
		}
	}
	return out
}

func matchingSignals(signals []*signalv1.Signal, labels store.LabelSelector) []*signalv1.Signal {
	var out []*signalv1.Signal
	for _, signal := range signals {
		if signal.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT && store.LabelsMatch(signal.GetLabels(), labels) {
			out = append(out, signal)
		}
	}
	return out
}

func (p *Processor) effectiveDetectionPolicyForAgent(agent store.AgentIdentity) *policyv1.DetectionPolicy {
	agent = agent.Normalized()
	if !agent.Valid() {
		policy, _ := p.store.EffectivePolicy("default", "", "", "")
		return policy.DetectionPolicy()
	}
	var scope agenthealth.RuntimeScope
	if health, ok := p.store.GetAgentHealth(agent.TenantID, agent.AgentID); ok {
		scope = health.Scope
	}
	policy, _ := p.store.EffectivePolicy(agent.TenantID, agent.AgentID, scope.Type, scope.Selector)
	return policy.DetectionPolicy()
}

func batchDocuments(batch *dataplanev1.DataBatch, fallback time.Time) ([]platformopensearch.Document, error) {
	var documents []platformopensearch.Document
	for _, frame := range batch.GetEvents() {
		ev := frame.GetEvent()
		if ev.GetId() == "" {
			continue
		}
		raw, err := protojson.Marshal(ev)
		if err != nil {
			return nil, fmt.Errorf("marshal event %q: %w", ev.GetId(), err)
		}
		documents = append(documents, decorateDocument(platformopensearch.Document{Index: platformopensearch.EventsWriteAlias, ID: ev.GetId(), Body: raw}, batch.GetHeader().GetTenantId(), frameTime(frame.GetObservedAt(), fallback)))
	}
	for _, frame := range batch.GetSignals() {
		sig := frame.GetSignal()
		doc, err := batchSignalDocument(sig, batch.GetHeader().GetTenantId(), batch.GetHeader().GetAgentId())
		if err != nil {
			return nil, err
		}
		if doc.ID != "" {
			documents = append(documents, decorateDocument(doc, batch.GetHeader().GetTenantId(), frameTime(frame.GetObservedAt(), fallback)))
		}
	}
	return documents, nil
}

func incidentDocuments(inc *incidentv1.Incident) ([]platformopensearch.Document, error) {
	if inc == nil || inc.GetId() == "" {
		return nil, nil
	}
	raw, err := protojson.Marshal(inc)
	if err != nil {
		return nil, fmt.Errorf("marshal incident %q: %w", inc.GetId(), err)
	}
	id := IncidentDocumentID(inc)
	documents := []platformopensearch.Document{}
	if inc.GetEvidence() == nil {
		return append(documents, platformopensearch.Document{Index: platformopensearch.IncidentsWriteAlias, ID: id, Body: raw}), nil
	}
	evidenceRaw, err := protojson.Marshal(inc.GetEvidence())
	if err != nil {
		return nil, fmt.Errorf("marshal incident evidence %q: %w", id, err)
	}
	documents = append(documents, platformopensearch.Document{Index: platformopensearch.EvidenceWriteAlias, ID: id + ":evidence", Body: evidenceRaw})
	documents = append(documents, platformopensearch.Document{Index: platformopensearch.IncidentsWriteAlias, ID: id, Body: raw})
	return documents, nil
}

func signalDocument(sig *signalv1.Signal) (platformopensearch.Document, error) {
	id := SignalDocumentID(sig)
	return signalDocumentWithID(sig, id)
}

func batchSignalDocument(sig *signalv1.Signal, tenantID, agentID string) (platformopensearch.Document, error) {
	if sig != nil && sig.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT {
		return signalDocumentWithID(sig, EndpointSignalDocumentID(tenantID, agentID, sig.GetId()))
	}
	return signalDocument(sig)
}

func signalDocumentWithID(sig *signalv1.Signal, id string) (platformopensearch.Document, error) {
	if id == "" {
		return platformopensearch.Document{}, nil
	}
	raw, err := protojson.Marshal(sig)
	if err != nil {
		return platformopensearch.Document{}, fmt.Errorf("marshal signal %q: %w", id, err)
	}
	return platformopensearch.Document{Index: platformopensearch.SignalsWriteAlias, ID: id, Body: raw}, nil
}

func EndpointSignalDocumentID(tenantID, agentID, signalID string) string {
	if strings.TrimSpace(signalID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tenantID + "\x00" + agentID + "\x00" + signalID))
	return "endpoint-signal:" + hex.EncodeToString(sum[:16])
}

func SignalDocumentID(sig *signalv1.Signal) string {
	if sig == nil {
		return ""
	}
	if sig.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_CLOUD {
		return store.SignalProjectionKey(sig)
	}
	if sig.GetId() != "" {
		return sig.GetId()
	}
	parts := []string{labelSelectorKey(analysisSelector(sig.GetLabels())), sig.GetName(), sig.GetLineageId()}
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	id := strings.Join(parts, ":")
	if strings.Trim(id, ":") == "" {
		return ""
	}
	return id
}

func IncidentDocumentID(inc *incidentv1.Incident) string {
	if inc == nil {
		return ""
	}
	identity := strings.Join([]string{inc.GetTenantId(), inc.GetCorrelationKey(), inc.GetAnalysisVersion()}, ":")
	if strings.Trim(identity, ":") == "" {
		labels := inc.GetLabels()
		identity = strings.Join([]string{labels["tenant_id"], labels["correlation_key"], labels["analysis_version"]}, ":")
	}
	if strings.Trim(identity, ":") != "" {
		sum := sha256.Sum256([]byte(identity))
		return "incident:" + hex.EncodeToString(sum[:16])
	}
	return inc.GetId()
}
