package contracts

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func SignalToDomain(value *signalv1.Signal) (domaintelemetry.Signal, error) {
	if value == nil {
		return domaintelemetry.Signal{}, fmt.Errorf("signal is required")
	}
	if err := validateSignalSemantics(value); err != nil {
		return domaintelemetry.Signal{}, err
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
		SignalRefs: append([]string(nil), value.GetSignalRefs()...),
		Stage:      domaintelemetry.SignalStage(value.GetStage()), DetectorKind: domaintelemetry.DetectorKind(value.GetDetectorKind()),
		Evidence: evidence, CrossLineage: value.GetCrossLineage(), Response: responseToDomain(value.ResponseIntent),
		RuleID: value.GetRuleId(), RuleVersion: value.GetRuleVersion(), RulesetRef: value.GetRulesetRef(), ModelRef: value.GetModelRef(), ModelVersion: value.GetModelVersion(), ModelDigest: value.GetModelDigest(), FeatureSchema: value.GetFeatureSchema(),
		ContextRefs: contextRefs, IOCRefs: iocRefs,
		Severity: value.GetSeverity(), Confidence: value.GetConfidence(), Mode: value.GetMode(), Labels: cloneLabels(value.GetLabels()),
	}, nil
}

func validateSignalSemantics(value *signalv1.Signal) error {
	switch value.GetStage() {
	case signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, signalv1.SignalStage_SIGNAL_STAGE_CONCLUSION:
	default:
		return fmt.Errorf("unsupported signal stage %q", value.GetStage())
	}
	switch value.GetDetectorKind() {
	case signalv1.DetectorKind_DETECTOR_KIND_RULE, signalv1.DetectorKind_DETECTOR_KIND_MODEL,
		signalv1.DetectorKind_DETECTOR_KIND_GRAPH, signalv1.DetectorKind_DETECTOR_KIND_SYSTEM:
	default:
		return fmt.Errorf("unsupported signal detector kind %q", value.GetDetectorKind())
	}
	if value.GetDetectorKind() == signalv1.DetectorKind_DETECTOR_KIND_MODEL {
		return validateModelCandidate(value)
	}
	if hasModelProvenance(value) {
		return fmt.Errorf("model provenance requires model detector kind")
	}
	return nil
}

func validateModelCandidate(value *signalv1.Signal) error {
	if value.GetStage() != signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE {
		return fmt.Errorf("model detector output must be a candidate")
	}
	if !hasCompleteModelProvenance(value) {
		return fmt.Errorf("model detector provenance is required")
	}
	if !validModelDigest(value.GetModelDigest()) || value.GetFeatureSchema() != "FeatureSchemaV1" {
		return fmt.Errorf("model detector provenance is invalid")
	}
	if value.GetWhere() != signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT || !validModelEventRefs(value.GetEventRefs()) {
		return fmt.Errorf("model detector output requires endpoint event evidence")
	}
	score := value.GetLocalRarity()
	if score < 0 || math.IsNaN(float64(score)) || math.IsInf(float64(score), 0) {
		return fmt.Errorf("model detector output local rarity must be finite and non-negative")
	}
	if value.GetRuleId() != "" || value.GetRuleVersion() != 0 || value.GetRulesetRef() != "" {
		return fmt.Errorf("model detector output cannot carry rule provenance")
	}
	if value.ResponseIntent != nil || value.GetGlobalRarity() != 0 {
		return fmt.Errorf("model detector output cannot carry response intent or global rarity")
	}
	return nil
}

func validModelDigest(value string) bool {
	encoded := strings.TrimPrefix(value, "sha256:")
	if len(encoded) != 64 || strings.ToLower(encoded) != encoded || len(encoded) == len(value) {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}

func validModelEventRefs(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func hasCompleteModelProvenance(value *signalv1.Signal) bool {
	return strings.TrimSpace(value.GetModelRef()) != "" && strings.TrimSpace(value.GetModelVersion()) != "" &&
		strings.TrimSpace(value.GetModelDigest()) != "" && strings.TrimSpace(value.GetFeatureSchema()) != ""
}

func hasModelProvenance(value *signalv1.Signal) bool {
	return value.GetModelRef() != "" || value.GetModelVersion() != "" || value.GetModelDigest() != "" || value.GetFeatureSchema() != ""
}

func SignalFromDomain(value domaintelemetry.Signal) *signalv1.Signal {
	return &signalv1.Signal{
		Id: value.ID, Name: value.Name, Where: whereFromDomain(value.Where), BaseRisk: value.BaseRisk,
		LocalRarity: value.LocalRarity, GlobalRarity: value.GlobalRarity, LineageId: value.LineageID,
		Entities: entitiesFromDomain(value.Entities), EventRefs: append([]string(nil), value.EventRefs...),
		SignalRefs: append([]string(nil), value.SignalRefs...),
		Stage:      signalv1.SignalStage(value.Stage), DetectorKind: signalv1.DetectorKind(value.DetectorKind),
		Evidence: evidenceFromDomain(value.Evidence), CrossLineage: value.CrossLineage, ResponseIntent: responseFromDomain(value.Response),
		RuleId: value.RuleID, RuleVersion: value.RuleVersion, RulesetRef: value.RulesetRef, ModelRef: value.ModelRef, ModelVersion: value.ModelVersion, ModelDigest: value.ModelDigest, FeatureSchema: value.FeatureSchema,
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
