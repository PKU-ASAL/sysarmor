package processing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	workerprocessing "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/worker/processing"
	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type Processor struct {
	engine    *workerprocessing.Engine
	projector ports.DocumentProjector
	history   ports.HistoryReader
	rarity    RarityReader
	batches   ports.TelemetryBatches
	policies  ports.DetectionPolicyReader
}

type RarityReader = ports.RarityReader

const (
	eventsIndex    = "sysarmor-events-write"
	signalsIndex   = "sysarmor-signals-write"
	incidentsIndex = "sysarmor-incidents-write"
	evidenceIndex  = "sysarmor-evidence-write"
)

type Result struct {
	AcceptedEvents  int
	AcceptedSignals int
	CloudSignals    int
	Incidents       int
	Duplicate       bool
}

func NewRemoteProcessor(projector ports.DocumentProjector, history ports.HistoryReader, rarityReader ports.RarityReader, batches ports.TelemetryBatches, policies ports.DetectionPolicyReader) *Processor {
	if projector == nil {
		projector = ports.NoopDocumentProjector{}
	}
	return &Processor{engine: workerprocessing.NewEngine(), projector: projector, history: history, rarity: rarityReader, batches: batches, policies: policies}
}

func (p *Processor) SetRarityReader(reader RarityReader)                       { p.rarity = reader }
func (p *Processor) SetTelemetryBatches(batches ports.TelemetryBatches)        { p.batches = batches }
func (p *Processor) SetDetectionPolicies(policies ports.DetectionPolicyReader) { p.policies = policies }

func (p *Processor) Process(ctx context.Context, batch *dataplanev1.DataBatch) (Result, error) {
	if p == nil || p.engine == nil || p.history == nil || p.rarity == nil || p.batches == nil || p.policies == nil {
		return Result{}, fmt.Errorf("ingest processor dependencies are incomplete")
	}
	if batch == nil || batch.GetHeader() == nil {
		return Result{}, fmt.Errorf("data batch header identity is required")
	}
	header := batch.GetHeader()
	claim, claimToken, err := p.batches.Claim(ctx, header.GetTenantId(), header.GetBatchId(), 30*time.Second)
	if err != nil {
		return Result{}, fmt.Errorf("claim telemetry batch: %w", err)
	}
	if claim == ports.TelemetryDuplicate {
		return Result{Duplicate: true}, nil
	}
	if claim == ports.TelemetryBusy {
		return Result{}, fmt.Errorf("telemetry batch is already processing")
	}
	committed := false
	defer func() {
		if !committed {
			_ = p.batches.Abandon(ctx, header.GetTenantId(), header.GetBatchId(), claimToken)
		}
	}()
	agent := agentIdentity{TenantID: header.GetTenantId(), AgentID: header.GetAgentId()}
	tenantID := agent.Normalized().TenantID
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
	}
	for _, frame := range batch.GetSignals() {
		sig := frame.GetSignal()
		currentSignals = append(currentSignals, sig)
		rememberTouchedScope(touchedScopes, sig.GetLabels(), agent)
	}
	start := time.Now()
	parsedTenant, err := tenant.NewID(tenantID)
	if err != nil {
		return Result{}, err
	}
	baseline, err := p.rarity.Rarity(ctx, parsedTenant)
	if err != nil {
		return Result{}, fmt.Errorf("load tenant rarity baseline: %w", err)
	}
	p.engine.SetRarityBaseline(rarity.Baseline{WorkloadCounts: baseline.WorkloadCounts})
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
	delta := telemetryBatchDelta(batch, claimToken, len(currentEvents), len(currentSignals), cloudSignals, incidents, convergenceLatency)
	if err := p.batches.Commit(ctx, delta); err != nil {
		return Result{}, err
	}
	committed = true
	return Result{AcceptedEvents: len(currentEvents), AcceptedSignals: len(currentSignals), CloudSignals: cloudSignals, Incidents: incidents}, nil
}

func telemetryBatchDelta(batch *dataplanev1.DataBatch, claimToken string, events, endpointSignals, cloudSignals, incidents int, latency time.Duration) ports.TelemetryBatchDelta {
	latencyMs := uint64(latency.Milliseconds())
	metrics := ports.TelemetryMetrics{
		DataBatches: 1, Events: uint64(events), EndpointSignals: uint64(endpointSignals),
		CloudSignals: uint64(cloudSignals), Signals: uint64(endpointSignals + cloudSignals),
		Incidents: uint64(incidents), LastLatencyMs: latencyMs,
		MaxLatencyMs: latencyMs, TotalLatencyMs: latencyMs, AverageLatencyMs: float64(latencyMs),
	}
	baseline := rarity.Baseline{}
	domainSignals := make([]domaintelemetry.Signal, 0, len(batch.GetSignals()))
	for _, frame := range batch.GetSignals() {
		if signal := frame.GetSignal(); signal != nil {
			if mapped, err := contractmapper.SignalToDomain(signal); err == nil {
				domainSignals = append(domainSignals, mapped)
			}
		}
	}
	baseline.Observe(domainSignals)
	return ports.TelemetryBatchDelta{TenantID: batch.GetHeader().GetTenantId(), BatchID: batch.GetHeader().GetBatchId(), ClaimToken: claimToken, Metrics: metrics, Rarity: identity.RarityBaseline{WorkloadCounts: baseline.WorkloadCounts}}
}

type touchedScope struct {
	labels labelSelector
	agent  agentIdentity
}

type agentIdentity struct{ TenantID, AgentID string }
type labelSelector map[string]string

func (agent agentIdentity) Normalized() agentIdentity { return agent }

func rememberTouchedScope(scopes map[string]touchedScope, labels map[string]string, agent agentIdentity) {
	selector := analysisSelector(labels)
	if len(selector) == 0 {
		return
	}
	scopes[labelSelectorKey(selector)] = touchedScope{labels: selector, agent: agent}
}

func analysisSelector(labels map[string]string) labelSelector {
	selector := labelSelector{}
	for _, key := range []string{"case_type", "scenario", "workload"} {
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

func (p *Processor) recomputeTouchedScopes(ctx context.Context, touchedScopes map[string]touchedScope, currentEvents []*eventv1.CanonicalEvent, currentSignals []*signalv1.Signal, upper time.Time) (int, int, []ports.SearchDocument, error) {
	totalCloud := 0
	totalIncidents := 0
	var documents []ports.SearchDocument
	for _, scope := range touchedScopes {
		historyDocs, err := p.history.ReadDocuments(ctx, scope.agent.Normalized().TenantID, scope.labels, upper.Add(-15*time.Minute), upper)
		if err != nil {
			return 0, 0, nil, err
		}
		historyEvents, err := decodeEvents(historyDocs.Events)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("decode event history: %w", err)
		}
		historySignals, err := decodeSignals(historyDocs.Signals)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("decode signal history: %w", err)
		}
		events := mergeEvents(historyEvents, matchingEvents(currentEvents, scope.labels))
		endpointSignals := mergeSignals(historySignals, matchingSignals(currentSignals, scope.labels))
		policy, err := p.effectiveDetectionPolicyForAgent(ctx, scope.agent)
		if err != nil {
			return 0, 0, nil, fmt.Errorf("read effective detection policy: %w", err)
		}
		analysis := analyzeWire(p.engine, events, endpointSignals, policy)
		firstObserved, lastObserved := incidentObservedRange(events)
		for _, inc := range analysis.Incidents {
			inc.TenantId = scope.agent.Normalized().TenantID
			inc.CorrelationKey = labelSelectorKey(scope.labels)
			inc.AnalysisVersion = "incident.v1"
			inc.FirstObservedAt = firstObserved
			inc.LastObservedAt = lastObserved
		}
		for _, sig := range analysis.CloudSignals {
			doc, err := signalDocumentWithID(sig, CloudSignalDocumentID(scope.agent.Normalized().TenantID, sig))
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

func analyzeWire(engine *workerprocessing.Engine, events []*eventv1.CanonicalEvent, signals []*signalv1.Signal, policy *domaindetection.Policy) AnalysisResult {
	domainEvents := make([]domaintelemetry.Event, 0, len(events))
	for _, event := range events {
		if mapped, err := contractmapper.EventToDomain(event); err == nil {
			domainEvents = append(domainEvents, mapped)
		}
	}
	domainSignals := make([]domaintelemetry.Signal, 0, len(signals))
	for _, signal := range signals {
		if mapped, err := contractmapper.SignalToDomain(signal); err == nil {
			domainSignals = append(domainSignals, mapped)
		}
	}
	result := engine.AnalyzeWithPolicy(domainEvents, domainSignals, policy)
	converted := AnalysisResult{}
	for _, signal := range result.CloudSignals {
		converted.CloudSignals = append(converted.CloudSignals, contractmapper.SignalFromDomain(signal))
	}
	for _, incident := range result.Incidents {
		converted.Incidents = append(converted.Incidents, contractmapper.IncidentFromDomain(incident))
	}
	return converted
}

type AnalysisResult struct {
	CloudSignals []*signalv1.Signal
	Incidents    []*incidentv1.Incident
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

func matchingEvents(events []*eventv1.CanonicalEvent, labels labelSelector) []*eventv1.CanonicalEvent {
	var out []*eventv1.CanonicalEvent
	for _, event := range events {
		if labelsMatch(event.GetLabels(), labels) {
			out = append(out, event)
		}
	}
	return out
}

func matchingSignals(signals []*signalv1.Signal, labels labelSelector) []*signalv1.Signal {
	var out []*signalv1.Signal
	for _, signal := range signals {
		if signal.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT && labelsMatch(signal.GetLabels(), labels) {
			out = append(out, signal)
		}
	}
	return out
}

func labelsMatch(values map[string]string, expected labelSelector) bool {
	for key, value := range expected {
		if values[key] != value {
			return false
		}
	}
	return true
}

func signalProjectionKey(signal *signalv1.Signal) string {
	if signal == nil {
		return ""
	}
	if signal.GetId() != "" {
		return signal.GetId()
	}
	return strings.Join([]string{signal.GetName(), signal.GetLineageId(), labelSelectorKey(analysisSelector(signal.GetLabels()))}, "\x00")
}

func (p *Processor) effectiveDetectionPolicyForAgent(ctx context.Context, agent agentIdentity) (*domaindetection.Policy, error) {
	agent = agent.Normalized()
	tenantID, err := tenant.NewID(agent.TenantID)
	if err != nil {
		return nil, err
	}
	policy, err := p.policies.Effective(ctx, tenantID, identity.AgentID(agent.AgentID))
	if err != nil {
		return nil, err
	}
	var wire struct {
		EndpointRules []string `json:"endpoint_rules"`
		CloudRules    []string `json:"cloud_rules"`
		Converge      *struct {
			Mode                  string `json:"mode"`
			CrossLineage          bool   `json:"cross_lineage"`
			AdditiveRiskThreshold uint32 `json:"additive_risk_threshold"`
		} `json:"converge"`
	}
	if err := json.Unmarshal(policy.Document, &wire); err != nil {
		return nil, fmt.Errorf("decode policy document: %w", err)
	}
	result := &domaindetection.Policy{EndpointRules: wire.EndpointRules, CloudRules: wire.CloudRules}
	if wire.Converge != nil {
		result.Converge = &domaindetection.ConvergePolicy{Mode: wire.Converge.Mode, CrossLineage: wire.Converge.CrossLineage, AdditiveRiskThreshold: wire.Converge.AdditiveRiskThreshold}
	}
	return result, nil
}

func EndpointSignalDocumentID(tenantID, agentID, signalID string) string {
	if strings.TrimSpace(signalID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tenantID + "\x00" + agentID + "\x00" + signalID))
	return "endpoint-signal:" + hex.EncodeToString(sum[:16])
}

func EventDocumentID(tenantID, agentID, eventID string) string {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(eventID) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tenantID + "\x00" + agentID + "\x00" + eventID))
	return "event:" + hex.EncodeToString(sum[:16])
}

func CloudSignalDocumentID(tenantID string, signal *signalv1.Signal) string {
	key := signalProjectionKey(signal)
	if strings.TrimSpace(tenantID) == "" || key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tenantID + "\x00" + key))
	return "cloud-signal:" + hex.EncodeToString(sum[:16])
}

func SignalDocumentID(sig *signalv1.Signal) string {
	if sig == nil {
		return ""
	}
	if sig.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_CLOUD {
		return signalProjectionKey(sig)
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
