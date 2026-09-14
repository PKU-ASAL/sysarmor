package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
)

func DecodePolicyDocument(document []byte) (domainpolicy.Policy, error) {
	var wire policyWire
	if err := json.Unmarshal(document, &wire); err != nil {
		return domainpolicy.Policy{}, fmt.Errorf("decode policy document: %w", err)
	}
	if err := validatePolicyWire(wire); err != nil {
		return domainpolicy.Policy{}, fmt.Errorf("decode policy document: %w", err)
	}
	value, err := domainPolicy(wire)
	if err != nil {
		return domainpolicy.Policy{}, err
	}
	return value, nil
}

func validatePolicyWire(wire policyWire) error {
	if strings.TrimSpace(wire.PolicyID) == "" {
		return fmt.Errorf("policy_id is required")
	}
	if wire.Version == 0 {
		return fmt.Errorf("version must be positive")
	}
	return nil
}

func EncodePolicyDocument(value domainpolicy.Policy) ([]byte, error) {
	wire, err := wirePolicy(value)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode policy document: %w", err)
	}
	return document, nil
}

func DecodeEndpointPolicy(document []byte) (domainpolicy.EndpointPolicy, error) {
	var wire endpointPolicyWire
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return domainpolicy.EndpointPolicy{}, fmt.Errorf("decode endpoint policy: %w", err)
	}
	return domainEndpointPolicy(wire)
}

func EncodeEndpointPolicy(value domainpolicy.EndpointPolicy) ([]byte, error) {
	collection, err := encodeCollectionDocument(value.Collection)
	if err != nil {
		return nil, err
	}
	wire := endpointPolicyWire{
		PolicyID: value.PolicyID, Version: value.Version,
		Collection: collection, Detection: wireDetection(value.Detection),
		Telemetry: wireTelemetry(value.Telemetry), Response: wireResponsePolicy(value.Response),
	}
	document, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint policy: %w", err)
	}
	return document, nil
}

func domainPolicy(wire policyWire) (domainpolicy.Policy, error) {
	value := domainpolicy.Policy{
		PolicyID: wire.PolicyID, Version: wire.Version, TenantID: wire.TenantID,
		Scope: domainScope(wire.Scope), EndpointRules: cloneStrings(wire.EndpointRules),
		CloudRules: cloneStrings(wire.CloudRules), Mode: wire.Mode,
		Converge: domainConverge(wire.Converge), Rarity: domainRarity(wire.Rarity),
		Response: domainResponsePolicy(wire.Response), Published: wire.Published,
		CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
	if wire.Detection != nil {
		value.Detection = domainDetection(wire.Detection)
	}
	if wire.Telemetry != nil {
		value.Telemetry = domainTelemetry(wire.Telemetry)
	}
	if wire.Collection != nil {
		collection, err := domainCollectionWire(*wire.Collection)
		if err != nil {
			return domainpolicy.Policy{}, err
		}
		value.Collection = &collection
	}
	return value, nil
}

func wirePolicy(value domainpolicy.Policy) (policyWire, error) {
	wire := policyWire{
		PolicyID: value.PolicyID, Version: value.Version, TenantID: value.TenantID,
		Scope: wireScope(value.Scope), EndpointRules: cloneStrings(value.EndpointRules),
		CloudRules: cloneStrings(value.CloudRules), Mode: value.Mode,
		Converge: wireConverge(value.Converge), Rarity: wireRarity(value.Rarity),
		Response: *wireResponsePolicy(value.Response), Published: value.Published,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
	if value.Detection != nil {
		wire.Detection = wireDetection(*value.Detection)
	}
	if value.Telemetry != nil {
		wire.Telemetry = wireTelemetry(*value.Telemetry)
	}
	if value.Collection != nil {
		collection, err := wireCollection(*value.Collection)
		if err != nil {
			return policyWire{}, err
		}
		wire.Collection = &collection
	}
	return wire, nil
}

func domainEndpointPolicy(wire endpointPolicyWire) (domainpolicy.EndpointPolicy, error) {
	collection, err := decodeCollectionDocument(wire.Collection)
	if err != nil {
		return domainpolicy.EndpointPolicy{}, err
	}
	candidate := domainpolicy.ActivationCandidate{
		Identity:   domainpolicy.Identity{ID: wire.PolicyID, Version: wire.Version},
		Collection: collection, Sections: domainpolicy.EndpointSections{
			Collection: len(wire.Collection) > 0, Detection: wire.Detection != nil,
			Telemetry: wire.Telemetry != nil, Response: wire.Response != nil,
		},
	}
	if err := candidate.Validate(); err != nil {
		return domainpolicy.EndpointPolicy{}, err
	}
	if wire.Detection.LearningModel != nil {
		model := wire.Detection.LearningModel
		if strings.TrimSpace(model.Ref) == "" || strings.TrimSpace(model.Version) == "" || strings.TrimSpace(model.Digest) == "" {
			return domainpolicy.EndpointPolicy{}, fmt.Errorf("learning model ref, version, and digest are required")
		}
	}
	response := domainResponsePolicy(*wire.Response)
	if len(response.AllowedActions) == 0 && len(response.AllowedModes) == 0 {
		response = defaultDomainResponsePolicy()
	}
	return domainpolicy.EndpointPolicy{
		PolicyID: wire.PolicyID, Version: wire.Version,
		Collection: domainpolicy.NormalizeCollection(collection),
		Detection:  domainpolicy.NormalizeDetectionPolicy(*domainDetection(wire.Detection)),
		Telemetry:  *domainTelemetry(wire.Telemetry), Response: response,
	}, nil
}

func domainDetection(wire *detectionWire) *domainpolicy.DetectionPolicy {
	if wire == nil {
		return nil
	}
	value := &domainpolicy.DetectionPolicy{
		PolicyID: wire.PolicyID, Version: wire.Version, Mode: wire.Mode,
		Scope: domainScope(wire.Scope),
	}
	for _, item := range wire.RuleSets {
		value.RuleSets = append(value.RuleSets, domainpolicy.RuleSetRef{
			Ref: item.Ref, Version: item.Version, Enabled: cloneBool(item.Enabled), IOCRefs: cloneStrings(item.IOCRefs),
		})
	}
	for _, item := range wire.RuleOverrides {
		value.RuleOverrides = append(value.RuleOverrides, domainRuleOverride(item))
	}
	value.ContextRefs = domainContentRefs(wire.ContextRefs)
	value.IOCRefs = domainContentRefs(wire.IOCRefs)
	if wire.LearningModel != nil {
		value.LearningModel = &domainpolicy.LearningModelRef{
			Ref: wire.LearningModel.Ref, Version: wire.LearningModel.Version, Digest: wire.LearningModel.Digest,
		}
	}
	return value
}

func wireDetection(value domainpolicy.DetectionPolicy) *detectionWire {
	wire := &detectionWire{
		PolicyID: value.PolicyID, Version: value.Version, Mode: value.Mode,
		Scope: wireScope(value.Scope),
	}
	for _, item := range value.RuleSets {
		wire.RuleSets = append(wire.RuleSets, ruleSetWire{
			Ref: item.Ref, Version: item.Version, Enabled: cloneBool(item.Enabled), IOCRefs: cloneStrings(item.IOCRefs),
		})
	}
	for _, item := range value.RuleOverrides {
		wire.RuleOverrides = append(wire.RuleOverrides, wireRuleOverride(item))
	}
	wire.ContextRefs = wireContentRefs(value.ContextRefs)
	wire.IOCRefs = wireContentRefs(value.IOCRefs)
	if value.LearningModel != nil {
		wire.LearningModel = &learningModelWire{
			Ref: value.LearningModel.Ref, Version: value.LearningModel.Version, Digest: value.LearningModel.Digest,
		}
	}
	return wire
}

func domainRuleOverride(wire ruleOverrideWire) domainpolicy.RuleOverride {
	value := domainpolicy.RuleOverride{
		RuleID: wire.RuleID, Enabled: cloneBool(wire.Enabled), Mode: wire.Mode,
		Severity: wire.Severity, Scope: domainScope(wire.Scope),
		Params: cloneMap(wire.Params), Reason: wire.Reason,
	}
	if wire.ResponseIntent != nil {
		value.ResponseIntent = &domainpolicy.ResponseIntentRef{
			Action: wire.ResponseIntent.Action, Confidence: wire.ResponseIntent.Confidence, Reason: wire.ResponseIntent.Reason,
		}
	}
	return value
}

func wireRuleOverride(value domainpolicy.RuleOverride) ruleOverrideWire {
	wire := ruleOverrideWire{
		RuleID: value.RuleID, Enabled: cloneBool(value.Enabled), Mode: value.Mode,
		Severity: value.Severity, Scope: wireScope(value.Scope),
		Params: cloneMap(value.Params), Reason: value.Reason,
	}
	if value.ResponseIntent != nil {
		wire.ResponseIntent = &responseIntentWire{
			Action: value.ResponseIntent.Action, Confidence: value.ResponseIntent.Confidence, Reason: value.ResponseIntent.Reason,
		}
	}
	return wire
}

func domainResponsePolicy(wire responsePolicyWire) domainresponse.Policy {
	modes := make([]domainresponse.Mode, 0, len(wire.AllowedModes))
	for _, mode := range wire.AllowedModes {
		modes = append(modes, domainresponse.Mode(mode))
	}
	return domainresponse.Policy{
		AllowedActions: cloneStrings(wire.AllowedActions), AllowedModes: modes,
		ApprovalRequired: wire.ApprovalRequired, ApprovalThreshold: wire.ApprovalThreshold,
		ApprovalRoles: cloneStrings(wire.ApprovalRoles), AllowDestructive: wire.AllowDestructive,
	}
}

func wireResponsePolicy(value domainresponse.Policy) *responsePolicyWire {
	modes := make([]string, 0, len(value.AllowedModes))
	for _, mode := range value.AllowedModes {
		modes = append(modes, string(mode))
	}
	return &responsePolicyWire{
		AllowedActions: cloneStrings(value.AllowedActions), AllowedModes: modes,
		ApprovalRequired: value.ApprovalRequired, ApprovalThreshold: value.ApprovalThreshold,
		ApprovalRoles: cloneStrings(value.ApprovalRoles), AllowDestructive: value.AllowDestructive,
	}
}

func defaultDomainResponsePolicy() domainresponse.Policy {
	return domainresponse.Policy{
		AllowedActions: []string{"collect", "noop"},
		AllowedModes:   []domainresponse.Mode{domainresponse.ModeObserve},
	}
}

func domainCollectionWire(wire collectionWire) (domainpolicy.CollectionPolicy, error) {
	document, err := json.Marshal(wire)
	if err != nil {
		return domainpolicy.CollectionPolicy{}, fmt.Errorf("encode collection wire: %w", err)
	}
	return decodeCollectionDocument(document)
}

func wireCollection(value domainpolicy.CollectionPolicy) (collectionWire, error) {
	document, err := encodeCollectionDocument(value)
	if err != nil {
		return collectionWire{}, err
	}
	var wire collectionWire
	if err := json.Unmarshal(document, &wire); err != nil {
		return collectionWire{}, fmt.Errorf("decode collection wire: %w", err)
	}
	return wire, nil
}

func domainTelemetry(value *telemetryWire) *domainpolicy.TelemetryPolicy {
	if value == nil {
		return nil
	}
	return &domainpolicy.TelemetryPolicy{
		MaxBatchItems: value.MaxBatchItems, MaxBatchBytes: value.MaxBatchBytes, FlushInterval: value.FlushInterval,
	}
}

func wireTelemetry(value domainpolicy.TelemetryPolicy) *telemetryWire {
	return &telemetryWire{
		MaxBatchItems: value.MaxBatchItems, MaxBatchBytes: value.MaxBatchBytes, FlushInterval: value.FlushInterval,
	}
}

func domainConverge(value *convergeWire) *domainpolicy.ConvergeParams {
	if value == nil {
		return nil
	}
	return &domainpolicy.ConvergeParams{
		Mode: value.Mode, TopK: value.TopK, MaxPathHops: value.MaxPathHops,
		AdditiveRiskThreshold: value.AdditiveRiskThreshold, CrossLineage: value.CrossLineage,
	}
}

func wireConverge(value *domainpolicy.ConvergeParams) *convergeWire {
	if value == nil {
		return nil
	}
	return &convergeWire{
		Mode: value.Mode, TopK: value.TopK, MaxPathHops: value.MaxPathHops,
		AdditiveRiskThreshold: value.AdditiveRiskThreshold, CrossLineage: value.CrossLineage,
	}
}

func domainRarity(value *rarityWire) *domainpolicy.RarityParams {
	if value == nil {
		return nil
	}
	return &domainpolicy.RarityParams{
		CMSWidth: value.CMSWidth, CMSDepth: value.CMSDepth, BaselineWindowNS: value.BaselineWindowNS,
	}
}

func wireRarity(value *domainpolicy.RarityParams) *rarityWire {
	if value == nil {
		return nil
	}
	return &rarityWire{
		CMSWidth: value.CMSWidth, CMSDepth: value.CMSDepth, BaselineWindowNS: value.BaselineWindowNS,
	}
}

func domainScope(value scopeWire) domainpolicy.ScopeSelector {
	return domainpolicy.ScopeSelector{Type: value.Type, Selector: value.Selector}
}

func wireScope(value domainpolicy.ScopeSelector) scopeWire {
	return scopeWire{Type: value.Type, Selector: value.Selector}
}

func domainContentRefs(values []contentRefWire) []domainpolicy.ContentRef {
	result := make([]domainpolicy.ContentRef, 0, len(values))
	for _, value := range values {
		result = append(result, domainpolicy.ContentRef{Ref: value.Ref, Version: value.Version})
	}
	return result
}

func wireContentRefs(values []domainpolicy.ContentRef) []contentRefWire {
	result := make([]contentRefWire, 0, len(values))
	for _, value := range values {
		result = append(result, contentRefWire{Ref: value.Ref, Version: value.Version})
	}
	return result
}

func cloneStrings(values []string) []string { return append([]string(nil), values...) }

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	cloned := make(map[string]string, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}
