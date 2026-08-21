package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

type ResolvedPolicyBundle struct {
	ProtectionMode   domainpolicy.EndpointProtectionMode
	ManagerDocument  json.RawMessage
	EndpointDocument json.RawMessage
}

type policyBundleWire struct {
	TenantID       string                              `json:"tenant_id,omitempty"`
	PolicyID       string                              `json:"policy_id"`
	Version        uint64                              `json:"version"`
	ProtectionMode domainpolicy.EndpointProtectionMode `json:"protection_mode"`
	Collection     json.RawMessage                     `json:"collection"`
	Detection      json.RawMessage                     `json:"detection"`
	Telemetry      json.RawMessage                     `json:"telemetry"`
	ResponsePolicy json.RawMessage                     `json:"response_policy"`
	Scope          json.RawMessage                     `json:"scope,omitempty"`
	EndpointRules  json.RawMessage                     `json:"endpoint_rules,omitempty"`
	CloudRules     json.RawMessage                     `json:"cloud_rules,omitempty"`
	Converge       json.RawMessage                     `json:"converge,omitempty"`
	Rarity         json.RawMessage                     `json:"rarity,omitempty"`
	Published      bool                                `json:"published,omitempty"`
	CreatedAt      json.RawMessage                     `json:"created_at,omitempty"`
	UpdatedAt      json.RawMessage                     `json:"updated_at,omitempty"`
}

type detectionCapabilitiesWire struct {
	PolicyID      string                  `json:"policy_id,omitempty"`
	Version       uint64                  `json:"version,omitempty"`
	Mode          string                  `json:"mode,omitempty"`
	Scope         json.RawMessage         `json:"scope,omitempty"`
	RuleSets      []ruleSetCapabilityWire `json:"rulesets,omitempty"`
	RuleOverrides json.RawMessage         `json:"rule_overrides,omitempty"`
	ContextRefs   json.RawMessage         `json:"context_refs,omitempty"`
	IOCRefs       json.RawMessage         `json:"ioc_refs,omitempty"`
	LearningModel *learningModelWire      `json:"learning_model,omitempty"`
}

type ruleSetCapabilityWire struct {
	Ref     string   `json:"ref"`
	Version string   `json:"version,omitempty"`
	Enabled *bool    `json:"enabled,omitempty"`
	IOCRefs []string `json:"ioc_refs,omitempty"`
}

type learningModelWire struct {
	Ref     string `json:"ref"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type collectionWire struct {
	Behaviors []json.RawMessage `json:"behaviors"`
}

type responseCapabilitiesWire struct {
	AllowedModes []string `json:"allowed_modes"`
}

func ResolvePolicyBundle(document []byte) (ResolvedPolicyBundle, error) {
	var wire policyBundleWire
	if err := decodeStrict(document, &wire); err != nil {
		return ResolvedPolicyBundle{}, fmt.Errorf("decode versioned policy bundle: %w", err)
	}
	detection, err := detectionCapabilities(wire.Detection)
	if err != nil {
		return ResolvedPolicyBundle{}, err
	}
	collection, behaviors, err := parseCollection(wire.Collection)
	if err != nil {
		return ResolvedPolicyBundle{}, err
	}
	response, err := responseCapabilities(wire.ResponsePolicy)
	if err != nil {
		return ResolvedPolicyBundle{}, err
	}
	bundle, err := domainpolicy.ResolveEndpointBundle(domainpolicy.VersionedBundle{
		ID: domainpolicy.ID(wire.PolicyID), Version: domainpolicy.Version(wire.Version),
		ProtectionMode: wire.ProtectionMode, CollectionBehaviors: behaviors,
		Detection: detection, Response: response,
		Sections: domainpolicy.EndpointSections{
			Collection: present(wire.Collection), Detection: present(wire.Detection),
			Telemetry: present(wire.Telemetry), Response: present(wire.ResponsePolicy),
		},
	})
	if err != nil {
		return ResolvedPolicyBundle{}, err
	}
	collection = addResolvedBehaviors(collection, behaviors, bundle.CollectionBehaviors)
	return encodeResolvedBundle(document, wire, collection)
}

func responseCapabilities(document json.RawMessage) (domainpolicy.ResponseCapabilities, error) {
	if !present(document) {
		return domainpolicy.ResponseCapabilities{}, nil
	}
	var wire responseCapabilitiesWire
	if err := json.Unmarshal(document, &wire); err != nil {
		return domainpolicy.ResponseCapabilities{}, fmt.Errorf("decode response policy: %w", err)
	}
	for _, mode := range wire.AllowedModes {
		if strings.EqualFold(strings.TrimSpace(mode), "enforce") {
			return domainpolicy.ResponseCapabilities{Enforce: true}, nil
		}
	}
	return domainpolicy.ResponseCapabilities{}, nil
}

func detectionCapabilities(document json.RawMessage) (domainpolicy.DetectionCapabilities, error) {
	if !present(document) {
		return domainpolicy.DetectionCapabilities{}, nil
	}
	var wire detectionCapabilitiesWire
	if err := decodeStrict(document, &wire); err != nil {
		return domainpolicy.DetectionCapabilities{}, fmt.Errorf("decode detection policy: %w", err)
	}
	capabilities := domainpolicy.DetectionCapabilities{Learning: wire.LearningModel != nil}
	for _, ruleset := range wire.RuleSets {
		if strings.TrimSpace(ruleset.Ref) != "" && (ruleset.Enabled == nil || *ruleset.Enabled) {
			capabilities.Rules = true
		}
	}
	if wire.LearningModel != nil && (strings.TrimSpace(wire.LearningModel.Ref) == "" || strings.TrimSpace(wire.LearningModel.Version) == "" || strings.TrimSpace(wire.LearningModel.Digest) == "") {
		return domainpolicy.DetectionCapabilities{}, fmt.Errorf("learning model ref, version, and digest are required")
	}
	return capabilities, nil
}

func parseCollection(document json.RawMessage) (collectionWire, []string, error) {
	var collection collectionWire
	if !present(document) {
		return collection, nil, nil
	}
	if err := json.Unmarshal(document, &collection); err != nil {
		return collectionWire{}, nil, fmt.Errorf("decode collection policy: %w", err)
	}
	behaviors := make([]string, 0, len(collection.Behaviors))
	for _, raw := range collection.Behaviors {
		var name string
		if json.Unmarshal(raw, &name) != nil {
			var structured struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &structured); err != nil {
				return collectionWire{}, nil, fmt.Errorf("decode collection behavior: %w", err)
			}
			name = structured.ID
		}
		behaviors = append(behaviors, name)
	}
	return collection, behaviors, nil
}

func addResolvedBehaviors(collection collectionWire, declared, resolved []string) collectionWire {
	known := make(map[string]bool, len(declared))
	for _, behavior := range declared {
		known[strings.ToLower(strings.TrimSpace(behavior))] = true
	}
	for _, behavior := range resolved {
		if !known[behavior] {
			raw, _ := json.Marshal(behavior)
			collection.Behaviors = append(collection.Behaviors, raw)
		}
	}
	return collection
}

func encodeResolvedBundle(document []byte, wire policyBundleWire, collection collectionWire) (ResolvedPolicyBundle, error) {
	collectionDocument, err := json.Marshal(collection)
	if err != nil {
		return ResolvedPolicyBundle{}, fmt.Errorf("encode resolved collection policy: %w", err)
	}
	var manager map[string]json.RawMessage
	if err := json.Unmarshal(document, &manager); err != nil {
		return ResolvedPolicyBundle{}, err
	}
	manager["collection"] = collectionDocument
	managerDocument, err := json.Marshal(manager)
	if err != nil {
		return ResolvedPolicyBundle{}, fmt.Errorf("encode resolved policy bundle: %w", err)
	}
	endpointDocument, err := json.Marshal(map[string]json.RawMessage{
		"policy_id": mustJSON(wire.PolicyID), "version": mustJSON(wire.Version),
		"collection": collectionDocument, "detection": wire.Detection,
		"telemetry": wire.Telemetry, "response": wire.ResponsePolicy,
	})
	if err != nil {
		return ResolvedPolicyBundle{}, fmt.Errorf("encode endpoint policy: %w", err)
	}
	return ResolvedPolicyBundle{wire.ProtectionMode, managerDocument, endpointDocument}, nil
}

func decodeStrict(document []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func present(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func mustJSON(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}
