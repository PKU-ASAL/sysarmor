package contracts

import (
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func Signal(value detection.Signal) *signalv1.Signal {
	return &signalv1.Signal{
		Id: value.ID, Name: value.Name, Where: signalWhere(value.Where), BaseRisk: value.BaseRisk,
		LocalRarity: value.LocalRarity, GlobalRarity: value.GlobalRarity, LineageId: value.LineageID,
		Entities: entities(value.Entities), EventRefs: cloneStrings(value.EventRefs), SignalRefs: cloneStrings(value.SignalRefs),
		Stage: signalStage(value.Stage), DetectorKind: detectorKind(value.DetectorKind),
		Evidence: evidence(value.Evidence), CrossLineage: value.CrossLineage,
		ResponseIntent: responseIntent(value.ResponseIntent), RuleId: value.RuleID, RuleVersion: value.RuleVersion,
		RulesetRef: value.RuleSetRef, ContextRefs: contentRefs(value.ContextRefs), IocRefs: contentRefs(value.IOCRefs),
		Severity: value.Severity, Confidence: value.Confidence, Mode: value.Mode, Labels: cloneLabels(value.Labels),
	}
}

func signalStage(value detection.SignalStage) signalv1.SignalStage {
	return signalv1.SignalStage(value)
}

func detectorKind(value detection.DetectorKind) signalv1.DetectorKind {
	return signalv1.DetectorKind(value)
}

func signalWhere(value detection.SignalWhere) signalv1.SignalWhere {
	switch value {
	case detection.SignalWhereEndpoint:
		return signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT
	case detection.SignalWhereCloud:
		return signalv1.SignalWhere_SIGNAL_WHERE_CLOUD
	default:
		return signalv1.SignalWhere_SIGNAL_WHERE_UNSPECIFIED
	}
}

func entities(values []detection.Entity) []*signalv1.EntityRef {
	out := make([]*signalv1.EntityRef, 0, len(values))
	for _, value := range values {
		out = append(out, &signalv1.EntityRef{Kind: value.Kind, Key: value.Key, Role: value.Role})
	}
	return out
}

func evidence(value *detection.Evidence) *signalv1.EvidenceBundle {
	if value == nil {
		return nil
	}
	return &signalv1.EvidenceBundle{
		Id: value.ID, EventRefs: cloneStrings(value.EventRefs), RawRefs: cloneStrings(value.RawRefs),
		Entities: entities(value.Entities), Summary: value.Summary,
	}
}

func responseIntent(value *detection.ResponseIntent) *signalv1.ResponseIntent {
	if value == nil {
		return nil
	}
	return &signalv1.ResponseIntent{
		ResponseIntent: value.Action, RecommendedAction: value.Action,
		Confidence: value.Confidence, Reason: value.Reason,
	}
}

func contentRefs(values []detection.ContentRef) []*signalv1.ContentRef {
	out := make([]*signalv1.ContentRef, 0, len(values))
	for _, value := range values {
		out = append(out, &signalv1.ContentRef{Ref: value.Ref, Version: value.Version, Digest: value.Digest})
	}
	return out
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
