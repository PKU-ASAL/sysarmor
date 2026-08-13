package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	eventsIndex    = "sysarmor-events-write"
	signalsIndex   = "sysarmor-signals-write"
	incidentsIndex = "sysarmor-incidents-write"
	evidenceIndex  = "sysarmor-evidence-write"
)

func projectionDocuments(projection ports.BatchProjection) ([]ports.SearchDocument, error) {
	documents, err := eventDocuments(projection)
	if err != nil {
		return nil, err
	}
	signals, err := signalDocuments(projection)
	if err != nil {
		return nil, err
	}
	documents = append(documents, signals...)
	for _, incident := range projection.Incidents {
		mapped, err := incidentDocuments(incident)
		if err != nil {
			return nil, err
		}
		for _, document := range mapped {
			documents = append(documents, decorateDocument(document, projection.TenantID.String(), projection.ObservedAt))
		}
	}
	return documents, nil
}

func eventDocuments(projection ports.BatchProjection) ([]ports.SearchDocument, error) {
	var result []ports.SearchDocument
	for _, observed := range projection.Events {
		if observed.Event.ID == "" {
			continue
		}
		raw, err := protojson.Marshal(contractmapper.EventFromDomain(observed.Event))
		if err != nil {
			return nil, fmt.Errorf("marshal event %q: %w", observed.Event.ID, err)
		}
		id := EventDocumentID(projection.TenantID.String(), string(projection.AgentID), observed.Event.ID)
		result = append(result, decorateDocument(ports.SearchDocument{Index: eventsIndex, ID: id, Body: raw}, projection.TenantID.String(), observedTime(observed.ObservedAt, projection.ObservedAt)))
	}
	return result, nil
}

func signalDocuments(projection ports.BatchProjection) ([]ports.SearchDocument, error) {
	var result []ports.SearchDocument
	for _, observed := range projection.Signals {
		id := CloudSignalDocumentID(projection.TenantID.String(), observed.Signal)
		if observed.Signal.Where == domaintelemetry.SignalWhereEndpoint {
			id = EndpointSignalDocumentID(projection.TenantID.String(), string(projection.AgentID), observed.Signal.ID)
		}
		document, err := signalDocument(observed.Signal, id)
		if err != nil {
			return nil, err
		}
		if document.ID != "" {
			result = append(result, decorateDocument(document, projection.TenantID.String(), observedTime(observed.ObservedAt, projection.ObservedAt)))
		}
	}
	for _, observed := range projection.CloudSignals {
		document, err := signalDocument(observed.Signal, CloudSignalDocumentID(projection.TenantID.String(), observed.Signal))
		if err != nil {
			return nil, err
		}
		if document.ID != "" {
			result = append(result, decorateDocument(document, projection.TenantID.String(), observedTime(observed.ObservedAt, projection.ObservedAt)))
		}
	}
	return result, nil
}

func signalDocument(signal domaintelemetry.Signal, id string) (ports.SearchDocument, error) {
	if id == "" {
		return ports.SearchDocument{}, nil
	}
	raw, err := protojson.Marshal(contractmapper.SignalFromDomain(signal))
	if err != nil {
		return ports.SearchDocument{}, fmt.Errorf("marshal signal %q: %w", id, err)
	}
	return ports.SearchDocument{Index: signalsIndex, ID: id, Body: raw}, nil
}

func incidentDocuments(incident domaintelemetry.Incident) ([]ports.SearchDocument, error) {
	if incident.ID == "" {
		return nil, nil
	}
	wire := contractmapper.IncidentFromDomain(incident)
	raw, err := protojson.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal incident %q: %w", incident.ID, err)
	}
	id := IncidentDocumentID(incident)
	if incident.Evidence == nil {
		return []ports.SearchDocument{{Index: incidentsIndex, ID: id, Body: raw}}, nil
	}
	evidence, err := protojson.Marshal(wire.GetEvidence())
	if err != nil {
		return nil, fmt.Errorf("marshal incident evidence %q: %w", id, err)
	}
	return []ports.SearchDocument{{Index: evidenceIndex, ID: id + ":evidence", Body: evidence}, {Index: incidentsIndex, ID: id, Body: raw}}, nil
}

func decorateDocument(document ports.SearchDocument, tenantID string, observed time.Time) ports.SearchDocument {
	var body map[string]any
	if json.Unmarshal(document.Body, &body) != nil {
		return document
	}
	delete(body, "tenantId")
	body["tenant_id"] = tenantID
	body["@timestamp"] = observed.UTC().Format(time.RFC3339Nano)
	document.Body, _ = json.Marshal(body)
	return document
}

func observedTime(value, fallback time.Time) time.Time {
	if value.IsZero() {
		return fallback.UTC()
	}
	return value.UTC()
}

func EndpointSignalDocumentID(tenantID, agentID, signalID string) string {
	if strings.TrimSpace(signalID) == "" {
		return ""
	}
	return stableDocumentID("endpoint-signal", tenantID+"\x00"+agentID+"\x00"+signalID)
}

func EventDocumentID(tenantID, agentID, eventID string) string {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(eventID) == "" {
		return ""
	}
	return stableDocumentID("event", tenantID+"\x00"+agentID+"\x00"+eventID)
}

func CloudSignalDocumentID(tenantID string, signal domaintelemetry.Signal) string {
	key := signalProjectionKey(signal)
	if strings.TrimSpace(tenantID) == "" || key == "" {
		return ""
	}
	return stableDocumentID("cloud-signal", tenantID+"\x00"+key)
}

func signalProjectionKey(signal domaintelemetry.Signal) string {
	if signal.ID != "" {
		return signal.ID
	}
	parts := []string{signal.Name, signal.LineageID}
	for _, key := range []string{"case_type", "scenario", "workload"} {
		parts = append(parts, strings.TrimSpace(signal.Labels[key]))
	}
	key := strings.Join(parts, "\x00")
	if strings.Trim(key, "\x00") == "" {
		return ""
	}
	return key
}

func IncidentDocumentID(incident domaintelemetry.Incident) string {
	identity := strings.Join([]string{incident.TenantID, incident.CorrelationKey, incident.AnalysisVersion}, ":")
	if strings.Trim(identity, ":") != "" {
		return stableDocumentID("incident", identity)
	}
	return incident.ID
}

func stableDocumentID(prefix, value string) string {
	sum := sha256.Sum256([]byte(value))
	return prefix + ":" + hex.EncodeToString(sum[:16])
}
