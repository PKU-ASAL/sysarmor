package ingestworker

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func decorateDocument(doc ports.SearchDocument, tenantID string, observed time.Time) ports.SearchDocument {
	var body map[string]any
	if json.Unmarshal(doc.Body, &body) != nil {
		return doc
	}
	delete(body, "tenantId")
	body["tenant_id"], body["@timestamp"] = tenantID, observed.UTC().Format(time.RFC3339Nano)
	doc.Body, _ = json.Marshal(body)
	return doc
}

func batchDocuments(batch *dataplanev1.DataBatch, fallback time.Time) ([]ports.SearchDocument, error) {
	var documents []ports.SearchDocument
	for _, frame := range batch.GetEvents() {
		event := frame.GetEvent()
		if event.GetId() == "" {
			continue
		}
		raw, err := protojson.Marshal(event)
		if err != nil {
			return nil, fmt.Errorf("marshal event %q: %w", event.GetId(), err)
		}
		id := EventDocumentID(batch.GetHeader().GetTenantId(), batch.GetHeader().GetAgentId(), event.GetId())
		documents = append(documents, decorateDocument(ports.SearchDocument{Index: eventsIndex, ID: id, Body: raw}, batch.GetHeader().GetTenantId(), frameTime(frame.GetObservedAt(), fallback)))
	}
	for _, frame := range batch.GetSignals() {
		doc, err := batchSignalDocument(frame.GetSignal(), batch.GetHeader().GetTenantId(), batch.GetHeader().GetAgentId())
		if err != nil {
			return nil, err
		}
		if doc.ID != "" {
			documents = append(documents, decorateDocument(doc, batch.GetHeader().GetTenantId(), frameTime(frame.GetObservedAt(), fallback)))
		}
	}
	return documents, nil
}

func incidentDocuments(incident *incidentv1.Incident) ([]ports.SearchDocument, error) {
	if incident == nil || incident.GetId() == "" {
		return nil, nil
	}
	raw, err := protojson.Marshal(incident)
	if err != nil {
		return nil, fmt.Errorf("marshal incident %q: %w", incident.GetId(), err)
	}
	id := IncidentDocumentID(incident)
	if incident.GetEvidence() == nil {
		return []ports.SearchDocument{{Index: incidentsIndex, ID: id, Body: raw}}, nil
	}
	evidence, err := protojson.Marshal(incident.GetEvidence())
	if err != nil {
		return nil, fmt.Errorf("marshal incident evidence %q: %w", id, err)
	}
	return []ports.SearchDocument{{Index: evidenceIndex, ID: id + ":evidence", Body: evidence}, {Index: incidentsIndex, ID: id, Body: raw}}, nil
}

func signalDocument(signal *signalv1.Signal) (ports.SearchDocument, error) {
	return signalDocumentWithID(signal, SignalDocumentID(signal))
}

func batchSignalDocument(signal *signalv1.Signal, tenantID, agentID string) (ports.SearchDocument, error) {
	if signal != nil && signal.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT {
		return signalDocumentWithID(signal, EndpointSignalDocumentID(tenantID, agentID, signal.GetId()))
	}
	return signalDocument(signal)
}

func signalDocumentWithID(signal *signalv1.Signal, id string) (ports.SearchDocument, error) {
	if id == "" {
		return ports.SearchDocument{}, nil
	}
	raw, err := protojson.Marshal(signal)
	if err != nil {
		return ports.SearchDocument{}, fmt.Errorf("marshal signal %q: %w", id, err)
	}
	return ports.SearchDocument{Index: signalsIndex, ID: id, Body: raw}, nil
}
