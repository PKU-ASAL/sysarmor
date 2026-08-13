package contracts

import (
	"fmt"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func SignalToDomain(value *signalv1.Signal) (domaintelemetry.Signal, error) {
	if value == nil {
		return domaintelemetry.Signal{}, fmt.Errorf("signal is required")
	}
	entities, err := entitiesToDomain(value.GetEntities())
	if err != nil {
		return domaintelemetry.Signal{}, err
	}
	evidence, err := evidenceToDomain(value.Evidence)
	if err != nil {
		return domaintelemetry.Signal{}, err
	}
	contextRefs, err := contentsToDomain(value.GetContextRefs())
	if err != nil {
		return domaintelemetry.Signal{}, err
	}
	iocRefs, err := contentsToDomain(value.GetIocRefs())
	if err != nil {
		return domaintelemetry.Signal{}, err
	}
	return domaintelemetry.Signal{
		ID: value.GetId(), Name: value.GetName(), Where: whereToDomain(value.GetWhere()), BaseRisk: value.GetBaseRisk(),
		LocalRarity: value.GetLocalRarity(), GlobalRarity: value.GetGlobalRarity(), LineageID: value.GetLineageId(),
		Entities: entities, EventRefs: append([]string(nil), value.GetEventRefs()...),
		SignalRefs: append([]string(nil), value.GetSignalRefs()...), Terminal: value.GetTerminal(),
		Evidence: evidence, CrossLineage: value.GetCrossLineage(), Response: responseToDomain(value.ResponseIntent),
		RuleID: value.GetRuleId(), RuleVersion: value.GetRuleVersion(), RulesetRef: value.GetRulesetRef(),
		ContextRefs: contextRefs, IOCRefs: iocRefs,
		Severity: value.GetSeverity(), Confidence: value.GetConfidence(), Mode: value.GetMode(), Labels: cloneLabels(value.GetLabels()),
	}, nil
}

func SignalFromDomain(value domaintelemetry.Signal) *signalv1.Signal {
	return &signalv1.Signal{
		Id: value.ID, Name: value.Name, Where: whereFromDomain(value.Where), BaseRisk: value.BaseRisk,
		LocalRarity: value.LocalRarity, GlobalRarity: value.GlobalRarity, LineageId: value.LineageID,
		Entities: entitiesFromDomain(value.Entities), EventRefs: append([]string(nil), value.EventRefs...),
		SignalRefs: append([]string(nil), value.SignalRefs...), Terminal: value.Terminal,
		Evidence: evidenceFromDomain(value.Evidence), CrossLineage: value.CrossLineage, ResponseIntent: responseFromDomain(value.Response),
		RuleId: value.RuleID, RuleVersion: value.RuleVersion, RulesetRef: value.RulesetRef,
		ContextRefs: contentsFromDomain(value.ContextRefs), IocRefs: contentsFromDomain(value.IOCRefs),
		Severity: value.Severity, Confidence: value.Confidence, Mode: value.Mode, Labels: cloneLabels(value.Labels),
	}
}

func whereToDomain(value signalv1.SignalWhere) domaintelemetry.SignalWhere {
	return domaintelemetry.SignalWhere(value)
}

func whereFromDomain(value domaintelemetry.SignalWhere) signalv1.SignalWhere {
	return signalv1.SignalWhere(value)
}

func entitiesToDomain(values []*signalv1.EntityRef) ([]domaintelemetry.Entity, error) {
	result := make([]domaintelemetry.Entity, 0, len(values))
	for index, value := range values {
		if value == nil {
			return nil, fmt.Errorf("entity %d is required", index)
		}
		result = append(result, domaintelemetry.Entity{Kind: value.GetKind(), Key: value.GetKey(), Role: value.GetRole()})
	}
	return result, nil
}

func entitiesFromDomain(values []domaintelemetry.Entity) []*signalv1.EntityRef {
	result := make([]*signalv1.EntityRef, 0, len(values))
	for _, value := range values {
		result = append(result, &signalv1.EntityRef{Kind: value.Kind, Key: value.Key, Role: value.Role})
	}
	return result
}

func evidenceToDomain(value *signalv1.EvidenceBundle) (*domaintelemetry.EvidenceBundle, error) {
	if value == nil {
		return nil, nil
	}
	entities, err := entitiesToDomain(value.GetEntities())
	if err != nil {
		return nil, fmt.Errorf("evidence: %w", err)
	}
	return &domaintelemetry.EvidenceBundle{
		ID: value.GetId(), EventRefs: append([]string(nil), value.GetEventRefs()...), RawRefs: append([]string(nil), value.GetRawRefs()...),
		Entities: entities, Summary: value.GetSummary(),
	}, nil
}

func evidenceFromDomain(value *domaintelemetry.EvidenceBundle) *signalv1.EvidenceBundle {
	if value == nil {
		return nil
	}
	return &signalv1.EvidenceBundle{
		Id: value.ID, EventRefs: append([]string(nil), value.EventRefs...), RawRefs: append([]string(nil), value.RawRefs...),
		Entities: entitiesFromDomain(value.Entities), Summary: value.Summary,
	}
}

func responseToDomain(value *signalv1.ResponseIntent) *domaintelemetry.ResponseIntent {
	if value == nil {
		return nil
	}
	return &domaintelemetry.ResponseIntent{Intent: value.GetResponseIntent(), RecommendedAction: value.GetRecommendedAction(), Confidence: value.GetConfidence(), Reason: value.GetReason()}
}

func responseFromDomain(value *domaintelemetry.ResponseIntent) *signalv1.ResponseIntent {
	if value == nil {
		return nil
	}
	return &signalv1.ResponseIntent{ResponseIntent: value.Intent, RecommendedAction: value.RecommendedAction, Confidence: value.Confidence, Reason: value.Reason}
}

func contentsToDomain(values []*signalv1.ContentRef) ([]domaintelemetry.ContentRef, error) {
	result := make([]domaintelemetry.ContentRef, 0, len(values))
	for index, value := range values {
		if value == nil {
			return nil, fmt.Errorf("content ref %d is required", index)
		}
		result = append(result, domaintelemetry.ContentRef{Ref: value.GetRef(), Version: value.GetVersion(), Digest: value.GetDigest()})
	}
	return result, nil
}

func contentsFromDomain(values []domaintelemetry.ContentRef) []*signalv1.ContentRef {
	result := make([]*signalv1.ContentRef, 0, len(values))
	for _, value := range values {
		result = append(result, &signalv1.ContentRef{Ref: value.Ref, Version: value.Version, Digest: value.Digest})
	}
	return result
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
