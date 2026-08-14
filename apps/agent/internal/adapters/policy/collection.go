package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type CollectionContentSnapshot struct {
	ContextSets map[string]CollectionValueSet
	IOCPacks    map[string]CollectionValueSet
}

type CollectionValueSet struct {
	Ref       string
	Version   string
	Digest    string
	ValueType string
	Values    []string
}

type CollectionExpansionReport struct {
	ResolvedRefs []contract.CollectionResolvedRef
}

func LoadCollectionIntent(path string, observeOnly bool) (contract.CollectionIntent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return contract.CollectionIntent{}, err
	}
	intent, err := ParseCollectionIntent(string(data), observeOnly)
	if err != nil {
		return contract.CollectionIntent{}, fmt.Errorf("%s: %w", path, err)
	}
	return intent, nil
}

func ParseCollectionIntent(data string, observeOnly bool) (contract.CollectionIntent, error) {
	if !strings.HasPrefix(strings.TrimSpace(data), "{") {
		return contract.CollectionIntent{}, fmt.Errorf("collection policy must be json with behaviors")
	}
	policy, err := ParseCollectionPolicyJSON([]byte(data), observeOnly)
	if err != nil {
		return contract.CollectionIntent{}, err
	}
	return CollectionPolicyIntent(policy)
}

func ParseCollectionPolicyJSON(data []byte, defaultObserveOnly bool) (domainpolicy.CollectionPolicy, error) {
	var envelope struct {
		Collection json.RawMessage `json:"collection"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return domainpolicy.CollectionPolicy{}, fmt.Errorf("decode collection policy: %w", err)
	}
	if len(envelope.Collection) > 0 {
		data = envelope.Collection
	}
	policy, err := decodeCollectionDocument(data)
	if err != nil {
		return domainpolicy.CollectionPolicy{}, err
	}
	if !policy.ObserveOnly {
		policy.ObserveOnly = defaultObserveOnly
	}
	return NormalizeCollectionPolicy(policy), nil
}

func NormalizeCollectionPolicy(value domainpolicy.CollectionPolicy) domainpolicy.CollectionPolicy {
	if strings.TrimSpace(value.Identity.ID) == "" {
		value.Identity.ID = "local-collection-policy"
	}
	if value.Identity.Version == 0 {
		value.Identity.Version = 1
	}
	return domainpolicy.NormalizeCollection(value)
}

func ExpandCollectionPolicyRefs(value domainpolicy.CollectionPolicy, snapshot CollectionContentSnapshot) (domainpolicy.CollectionPolicy, CollectionExpansionReport, error) {
	expanded, report, err := domainpolicy.ExpandCollection(value, domainContentSnapshot(snapshot))
	if err != nil {
		return domainpolicy.CollectionPolicy{}, CollectionExpansionReport{}, err
	}
	return expanded, sharedExpansionReport(report), nil
}

func CollectionPolicyIntent(value domainpolicy.CollectionPolicy) (contract.CollectionIntent, error) {
	intent, err := domainpolicy.CompileCollectionIntent(value)
	if err != nil {
		return contract.CollectionIntent{}, err
	}
	return contractmapper.SensorCollectionIntent(intent).NormalizeScope()
}

func WithScope(intent contract.CollectionIntent, scopeType, scopeSelector string) contract.CollectionIntent {
	intent.ScopeType = strings.TrimSpace(scopeType)
	intent.ScopeSelector = strings.TrimSpace(scopeSelector)
	return intent
}

func domainContentSnapshot(value CollectionContentSnapshot) domainpolicy.ContentSnapshot {
	return domainpolicy.ContentSnapshot{
		ContextSets: domainValueSets(value.ContextSets),
		IOCPacks:    domainValueSets(value.IOCPacks),
	}
}

func domainValueSets(values map[string]CollectionValueSet) map[string]domainpolicy.ValueSet {
	result := make(map[string]domainpolicy.ValueSet, len(values))
	for key, value := range values {
		result[key] = domainpolicy.ValueSet{Ref: value.Ref, Version: value.Version, Digest: value.Digest, ValueType: value.ValueType, Values: append([]string(nil), value.Values...)}
	}
	return result
}

func sharedExpansionReport(value domainpolicy.ExpansionReport) CollectionExpansionReport {
	result := CollectionExpansionReport{ResolvedRefs: make([]contract.CollectionResolvedRef, 0, len(value.ResolvedRefs))}
	for _, ref := range value.ResolvedRefs {
		result.ResolvedRefs = append(result.ResolvedRefs, contract.CollectionResolvedRef{Behavior: ref.Behavior, Selector: ref.Selector, Ref: ref.Ref, Version: ref.Version, Digest: ref.Digest, ValueType: ref.ValueType, Count: ref.Count, Values: append([]string(nil), ref.Values...)})
	}
	return result
}
