package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type CollectionPolicy = policymodel.CollectionPolicy
type CollectionBehaviorPolicy = policymodel.CollectionBehaviorPolicy
type CollectionBehaviorSelectors = policymodel.CollectionBehaviorSelectors
type BinarySelector = policymodel.BinarySelector
type ProcessSelector = policymodel.ProcessSelector
type FileSelector = policymodel.FileSelector
type SocketSelector = policymodel.SocketSelector

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

func ParseCollectionPolicyJSON(data []byte, defaultObserveOnly bool) (CollectionPolicy, error) {
	var envelope struct {
		Collection json.RawMessage `json:"collection"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return CollectionPolicy{}, fmt.Errorf("decode collection policy: %w", err)
	}
	if len(envelope.Collection) > 0 {
		data = envelope.Collection
	}
	var policy CollectionPolicy
	if err := decodeCollectionPolicy(data, &policy); err != nil {
		return CollectionPolicy{}, err
	}
	if !policy.ObserveOnly {
		policy.ObserveOnly = defaultObserveOnly
	}
	return NormalizeCollectionPolicy(policy), nil
}

func decodeCollectionPolicy(data []byte, policy *CollectionPolicy) error {
	var wire struct {
		PolicyID       string          `json:"policy_id,omitempty"`
		Version        uint64          `json:"version,omitempty"`
		Behaviors      json.RawMessage `json:"behaviors,omitempty"`
		BinaryPrefixes []string        `json:"binary_prefixes,omitempty"`
		FilePrefixes   []string        `json:"file_prefixes,omitempty"`
		SocketFamilies []string        `json:"socket_families,omitempty"`
		SocketAddrs    []string        `json:"socket_addrs,omitempty"`
		SocketPorts    []string        `json:"socket_ports,omitempty"`
		ScopeType      string          `json:"scope_type,omitempty"`
		ScopeSelector  string          `json:"scope_selector,omitempty"`
		ObserveOnly    bool            `json:"observe_only,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode collection policy: %w", err)
	}
	policy.PolicyID, policy.Version = wire.PolicyID, wire.Version
	policy.BinaryPrefixes, policy.FilePrefixes = wire.BinaryPrefixes, wire.FilePrefixes
	policy.SocketFamilies, policy.SocketAddrs, policy.SocketPorts = wire.SocketFamilies, wire.SocketAddrs, wire.SocketPorts
	policy.ScopeType, policy.ScopeSelector, policy.ObserveOnly = wire.ScopeType, wire.ScopeSelector, wire.ObserveOnly
	if len(wire.Behaviors) == 0 {
		return nil
	}
	if err := json.Unmarshal(wire.Behaviors, &policy.Behaviors); err == nil {
		return nil
	}
	if err := json.Unmarshal(wire.Behaviors, &policy.BehaviorSpecs); err != nil {
		return fmt.Errorf("decode collection behaviors: %w", err)
	}
	return nil
}

func NormalizeCollectionPolicy(value CollectionPolicy) CollectionPolicy {
	if strings.TrimSpace(value.PolicyID) == "" {
		value.PolicyID = "local-collection-policy"
	}
	if value.Version == 0 {
		value.Version = 1
	}
	return contractmapper.SharedCollectionPolicy(domainpolicy.NormalizeCollection(contractmapper.DomainCollectionPolicy(value)))
}

func ExpandCollectionPolicyRefs(value CollectionPolicy, snapshot CollectionContentSnapshot) (CollectionPolicy, CollectionExpansionReport, error) {
	expanded, report, err := domainpolicy.ExpandCollection(contractmapper.DomainCollectionPolicy(value), domainContentSnapshot(snapshot))
	if err != nil {
		return CollectionPolicy{}, CollectionExpansionReport{}, err
	}
	return contractmapper.SharedCollectionPolicy(expanded), sharedExpansionReport(report), nil
}

func CollectionPolicyIntent(value CollectionPolicy) (contract.CollectionIntent, error) {
	intent, err := domainpolicy.CompileCollectionIntent(contractmapper.DomainCollectionPolicy(value))
	if err != nil {
		return contract.CollectionIntent{}, err
	}
	return sensorCollectionIntent(intent).NormalizeScope()
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

func sensorCollectionIntent(value domainpolicy.CollectionIntent) contract.CollectionIntent {
	result := contract.CollectionIntent{Behaviors: append([]string(nil), value.Behaviors...), BinaryPrefixes: append([]string(nil), value.BinaryPrefixes...), FilePrefixes: append([]string(nil), value.FilePrefixes...), SocketFamilies: append([]string(nil), value.SocketFamilies...), SocketAddrs: append([]string(nil), value.SocketAddrs...), SocketPorts: append([]string(nil), value.SocketPorts...), ScopeType: value.ScopeType, ScopeSelector: value.ScopeSelector, ObserveOnly: value.ObserveOnly}
	for _, filter := range value.BehaviorFilters {
		result.BehaviorFilters = append(result.BehaviorFilters, contract.CollectionBehaviorFilter{Behavior: filter.Behavior, BinaryPrefixes: append([]string(nil), filter.BinaryPrefixes...), FilePrefixes: append([]string(nil), filter.FilePrefixes...), SocketFamilies: append([]string(nil), filter.SocketFamilies...), SocketAddrs: append([]string(nil), filter.SocketAddrs...), SocketPorts: append([]string(nil), filter.SocketPorts...)})
	}
	return result
}
