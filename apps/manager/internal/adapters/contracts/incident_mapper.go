package contracts

import (
	"fmt"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func IncidentToDomain(value *incidentv1.Incident) (domaintelemetry.Incident, error) {
	if value == nil {
		return domaintelemetry.Incident{}, fmt.Errorf("incident is required")
	}
	evidence, err := subgraphToDomain(value.Evidence)
	if err != nil {
		return domaintelemetry.Incident{}, err
	}
	signals, err := signalsToDomain(value.GetContributingSignals())
	if err != nil {
		return domaintelemetry.Incident{}, err
	}
	hasConclusion := false
	for _, signal := range signals {
		if signal.Stage == domaintelemetry.SignalStageConclusion {
			hasConclusion = true
			break
		}
	}
	if !hasConclusion {
		return domaintelemetry.Incident{}, fmt.Errorf("incident requires at least one conclusion signal")
	}
	return domaintelemetry.Incident{
		ID: value.GetId(), Summary: value.GetSummary(), Severity: value.GetSeverity(), MITRE: append([]string(nil), value.GetMitre()...),
		LineageIDs: append([]string(nil), value.GetLineageIds()...), ConclusionEntities: append([]string(nil), value.GetConclusionEntities()...),
		Evidence: evidence, Converge: convergeToDomain(value.Converge),
		ContributingSignals: signals, Labels: cloneLabels(value.GetLabels()),
		TenantID: value.GetTenantId(), CorrelationKey: value.GetCorrelationKey(), AnalysisVersion: value.GetAnalysisVersion(),
		FirstObservedAt: value.GetFirstObservedAt(), LastObservedAt: value.GetLastObservedAt(),
	}, nil
}

func IncidentFromDomain(value domaintelemetry.Incident) *incidentv1.Incident {
	return &incidentv1.Incident{
		Id: value.ID, Summary: value.Summary, Severity: value.Severity, Mitre: append([]string(nil), value.MITRE...),
		LineageIds: append([]string(nil), value.LineageIDs...), ConclusionEntities: append([]string(nil), value.ConclusionEntities...),
		Evidence: subgraphFromDomain(value.Evidence), Converge: convergeFromDomain(value.Converge),
		ContributingSignals: signalsFromDomain(value.ContributingSignals), Labels: cloneLabels(value.Labels),
		TenantId: value.TenantID, CorrelationKey: value.CorrelationKey, AnalysisVersion: value.AnalysisVersion,
		FirstObservedAt: value.FirstObservedAt, LastObservedAt: value.LastObservedAt,
	}
}

func subgraphToDomain(value *incidentv1.EvidenceSubgraph) (*domaintelemetry.EvidenceSubgraph, error) {
	if value == nil {
		return nil, nil
	}
	result := &domaintelemetry.EvidenceSubgraph{}
	for index, node := range value.GetNodes() {
		if node == nil {
			return nil, fmt.Errorf("graph node %d is required", index)
		}
		entities, err := entitiesToDomain(node.GetEntities())
		if err != nil {
			return nil, fmt.Errorf("graph node %d: %w", index, err)
		}
		result.Nodes = append(result.Nodes, domaintelemetry.GraphNode{ID: node.GetId(), Kind: node.GetKind(), Label: node.GetLabel(), Entities: entities})
	}
	for index, edge := range value.GetEdges() {
		if edge == nil {
			return nil, fmt.Errorf("graph edge %d is required", index)
		}
		result.Edges = append(result.Edges, domaintelemetry.GraphEdge{ID: edge.GetId(), From: edge.GetFrom(), To: edge.GetTo(), Kind: edge.GetKind(), EventRefs: append([]string(nil), edge.GetEventRefs()...), Incomplete: edge.GetIncomplete()})
	}
	return result, nil
}

func subgraphFromDomain(value *domaintelemetry.EvidenceSubgraph) *incidentv1.EvidenceSubgraph {
	if value == nil {
		return nil
	}
	result := &incidentv1.EvidenceSubgraph{}
	for _, node := range value.Nodes {
		result.Nodes = append(result.Nodes, &incidentv1.GraphNode{Id: node.ID, Kind: node.Kind, Label: node.Label, Entities: entitiesFromDomain(node.Entities)})
	}
	for _, edge := range value.Edges {
		result.Edges = append(result.Edges, &incidentv1.GraphEdge{Id: edge.ID, From: edge.From, To: edge.To, Kind: edge.Kind, EventRefs: append([]string(nil), edge.EventRefs...), Incomplete: edge.Incomplete})
	}
	return result
}

func convergeToDomain(value *incidentv1.ConvergeTrace) *domaintelemetry.ConvergeTrace {
	if value == nil {
		return nil
	}
	return &domaintelemetry.ConvergeTrace{
		Method: value.GetMethod(), SeedIDs: append([]string(nil), value.GetSeedIds()...), PathIDs: append([]string(nil), value.GetPathIds()...),
		Score: value.GetScore(), Controls: append([]string(nil), value.GetControls()...),
	}
}

func convergeFromDomain(value *domaintelemetry.ConvergeTrace) *incidentv1.ConvergeTrace {
	if value == nil {
		return nil
	}
	return &incidentv1.ConvergeTrace{
		Method: value.Method, SeedIds: append([]string(nil), value.SeedIDs...), PathIds: append([]string(nil), value.PathIDs...),
		Score: value.Score, Controls: append([]string(nil), value.Controls...),
	}
}

func signalsToDomain(values []*signalv1.Signal) ([]domaintelemetry.Signal, error) {
	result := make([]domaintelemetry.Signal, 0, len(values))
	for index, value := range values {
		signal, err := SignalToDomain(value)
		if err != nil {
			return nil, fmt.Errorf("contributing signal %d: %w", index, err)
		}
		result = append(result, signal)
	}
	return result, nil
}

func signalsFromDomain(values []domaintelemetry.Signal) []*signalv1.Signal {
	result := make([]*signalv1.Signal, 0, len(values))
	for _, value := range values {
		result = append(result, SignalFromDomain(value))
	}
	return result
}
