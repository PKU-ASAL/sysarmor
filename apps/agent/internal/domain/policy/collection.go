package policy

import (
	"fmt"
	"strings"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

const (
	maxFilePrefixes = 128
	maxSocketAddrs  = 512
	maxSocketPorts  = 128
)

var mandatoryCausalityBehaviors = []string{
	domainevent.BehaviorProcessExec,
	domainevent.BehaviorProcessExit,
	domainevent.BehaviorFileWrite,
	domainevent.BehaviorNetworkConnect,
}

type CollectionPolicy struct {
	Identity       Identity
	Behaviors      []string
	BehaviorSpecs  []BehaviorPolicy
	BinaryPrefixes []string
	FilePrefixes   []string
	SocketFamilies []string
	SocketAddrs    []string
	SocketPorts    []string
	ScopeType      string
	ScopeSelector  string
	ObserveOnly    bool
}

type BehaviorPolicy struct {
	ID        string
	Enabled   *bool
	Selectors BehaviorSelectors
}

type BehaviorSelectors struct {
	Binary  BinarySelector
	Process ProcessSelector
	File    FileSelector
	Socket  SocketSelector
}

type BinarySelector struct{ Prefixes []string }
type ProcessSelector struct{ BinaryPrefixes []string }
type FileSelector struct {
	Prefixes   []string
	PrefixRefs []string
}
type SocketSelector struct {
	Families []string
	Addrs    []string
	AddrRefs []string
	Ports    []string
	PortRefs []string
}

type ContentSnapshot struct {
	ContextSets map[string]ValueSet
	IOCPacks    map[string]ValueSet
}

type ValueSet struct {
	Ref, Version, Digest, ValueType string
	Values                          []string
}

type ResolvedRef struct {
	Behavior, Selector, Ref, Version, Digest, ValueType string
	Count                                               int
	Values                                              []string
}

type ExpansionReport struct{ ResolvedRefs []ResolvedRef }

type CollectionIntent struct {
	Behaviors                                                 []string
	MandatoryBehaviors                                        []string
	BinaryPrefixes, FilePrefixes, SocketFamilies, SocketAddrs []string
	SocketPorts                                               []string
	BehaviorFilters                                           []BehaviorFilter
	ScopeType, ScopeSelector                                  string
	ObserveOnly                                               bool
}

type BehaviorFilter struct {
	Behavior                                                  string
	BinaryPrefixes, FilePrefixes, SocketFamilies, SocketAddrs []string
	SocketPorts                                               []string
}

func NormalizeCollection(value CollectionPolicy) CollectionPolicy {
	value = cloneCollection(value)
	value.Identity.ID = strings.TrimSpace(value.Identity.ID)
	value.Behaviors = normalizeBehaviors(value.Behaviors)
	value.BinaryPrefixes = normalizeStrings(value.BinaryPrefixes)
	value.FilePrefixes = normalizeStrings(value.FilePrefixes)
	value.SocketFamilies = normalizeStrings(value.SocketFamilies)
	value.SocketAddrs = normalizeStrings(value.SocketAddrs)
	value.SocketPorts = normalizeStrings(value.SocketPorts)
	value.ScopeType = strings.TrimSpace(value.ScopeType)
	value.ScopeSelector = strings.TrimSpace(value.ScopeSelector)
	normalizedSpecs := make([]BehaviorPolicy, 0, len(value.BehaviorSpecs))
	for index := range value.BehaviorSpecs {
		normalizeBehaviorPolicy(&value.BehaviorSpecs[index])
		if value.BehaviorSpecs[index].ID != "" {
			normalizedSpecs = append(normalizedSpecs, value.BehaviorSpecs[index])
		}
	}
	value.BehaviorSpecs = normalizedSpecs
	return value
}

func ExpandCollection(value CollectionPolicy, snapshot ContentSnapshot) (CollectionPolicy, ExpansionReport, error) {
	value = NormalizeCollection(value)
	var report ExpansionReport
	for index := range value.BehaviorSpecs {
		spec := &value.BehaviorSpecs[index]
		resolved, err := expandBehavior(spec, snapshot, &report)
		if err != nil {
			return CollectionPolicy{}, ExpansionReport{}, err
		}
		*spec = resolved
	}
	return NormalizeCollection(value), report, nil
}

func expandBehavior(spec *BehaviorPolicy, snapshot ContentSnapshot, report *ExpansionReport) (BehaviorPolicy, error) {
	groups := []struct {
		selector string
		refs     []string
		allowed  []string
		budget   int
		target   *[]string
	}{
		{"file.path.prefix", spec.Selectors.File.PrefixRefs, []string{"path_prefix"}, maxFilePrefixes, &spec.Selectors.File.Prefixes},
		{"socket.addr", spec.Selectors.Socket.AddrRefs, []string{"ip", "addr", "ip_addr"}, maxSocketAddrs, &spec.Selectors.Socket.Addrs},
		{"socket.port", spec.Selectors.Socket.PortRefs, []string{"port"}, maxSocketPorts, &spec.Selectors.Socket.Ports},
	}
	for _, group := range groups {
		values, refs, err := expandRefs(snapshot, spec.ID, group.selector, group.refs, group.allowed, group.budget)
		if err != nil {
			return BehaviorPolicy{}, err
		}
		*group.target = normalizeStrings(append(*group.target, values...))
		report.ResolvedRefs = append(report.ResolvedRefs, refs...)
	}
	if len(spec.Selectors.File.Prefixes) > maxFilePrefixes {
		return BehaviorPolicy{}, selectorBudgetError(spec.ID, "file.path.prefix", len(spec.Selectors.File.Prefixes), maxFilePrefixes)
	}
	if len(spec.Selectors.Socket.Addrs) > maxSocketAddrs {
		return BehaviorPolicy{}, selectorBudgetError(spec.ID, "socket.addr", len(spec.Selectors.Socket.Addrs), maxSocketAddrs)
	}
	if len(spec.Selectors.Socket.Ports) > maxSocketPorts {
		return BehaviorPolicy{}, selectorBudgetError(spec.ID, "socket.port", len(spec.Selectors.Socket.Ports), maxSocketPorts)
	}
	return *spec, nil
}

func selectorBudgetError(behavior, selector string, count, budget int) error {
	return fmt.Errorf("collection selector %s for %s exceeds budget: %d > %d", selector, behavior, count, budget)
}

func expandRefs(snapshot ContentSnapshot, behavior, selector string, refs, allowed []string, budget int) ([]string, []ResolvedRef, error) {
	var values []string
	var resolved []ResolvedRef
	for _, ref := range normalizeStrings(refs) {
		set, ok := lookupValueSet(snapshot, ref)
		if !ok {
			return nil, nil, fmt.Errorf("collection selector %s for %s references missing content %q", selector, behavior, ref)
		}
		if !contains(allowed, strings.TrimSpace(set.ValueType)) {
			return nil, nil, fmt.Errorf("collection selector %s for %s references %s with invalid value type %q", selector, behavior, ref, set.ValueType)
		}
		values = normalizeStrings(append(values, set.Values...))
		if len(values) > budget {
			return nil, nil, fmt.Errorf("collection selector %s for %s exceeds budget: %d > %d", selector, behavior, len(values), budget)
		}
		resolved = append(resolved, ResolvedRef{Behavior: behavior, Selector: selector, Ref: set.Ref, Version: set.Version, Digest: set.Digest, ValueType: set.ValueType, Count: len(set.Values), Values: append([]string(nil), set.Values...)})
	}
	return values, resolved, nil
}

func CompileCollectionIntent(value CollectionPolicy) (CollectionIntent, error) {
	value = NormalizeCollection(value)
	seen := map[string]bool{}
	var behaviors []string
	add := func(raw string) error {
		behavior := domainevent.NormalizeBehavior(raw)
		if behavior == "" {
			return nil
		}
		if !knownBehavior(behavior) {
			return fmt.Errorf("unsupported collection behavior %q", raw)
		}
		if !seen[behavior] {
			seen[behavior], behaviors = true, append(behaviors, behavior)
		}
		return nil
	}
	for _, behavior := range mandatoryCausalityBehaviors {
		if err := add(behavior); err != nil {
			return CollectionIntent{}, err
		}
	}
	for _, behavior := range value.Behaviors {
		if err := add(behavior); err != nil {
			return CollectionIntent{}, err
		}
	}
	var filters []BehaviorFilter
	for _, spec := range value.BehaviorSpecs {
		if spec.Enabled != nil && !*spec.Enabled {
			continue
		}
		if err := add(spec.ID); err != nil {
			return CollectionIntent{}, err
		}
		filters = append(filters, behaviorFilter(spec))
	}
	if len(filters) == 0 {
		filters = flatBehaviorFilters(behaviors, value)
	}
	return CollectionIntent{Behaviors: behaviors, MandatoryBehaviors: clone(mandatoryCausalityBehaviors), BinaryPrefixes: clone(value.BinaryPrefixes), FilePrefixes: clone(value.FilePrefixes), SocketFamilies: clone(value.SocketFamilies), SocketAddrs: clone(value.SocketAddrs), SocketPorts: clone(value.SocketPorts), BehaviorFilters: mandatoryFilters(behaviors, filters), ScopeType: value.ScopeType, ScopeSelector: value.ScopeSelector, ObserveOnly: value.ObserveOnly}, nil
}

func mandatoryFilters(behaviors []string, filters []BehaviorFilter) []BehaviorFilter {
	result := make([]BehaviorFilter, 0, len(behaviors))
	for _, behavior := range behaviors {
		if contains(mandatoryCausalityBehaviors, behavior) {
			result = append(result, BehaviorFilter{Behavior: behavior})
			continue
		}
		for _, filter := range filters {
			if filter.Behavior == behavior {
				result = append(result, filter)
				break
			}
		}
	}
	return result
}

func normalizeBehaviorPolicy(value *BehaviorPolicy) {
	value.ID = domainevent.NormalizeBehavior(value.ID)
	value.Selectors.Binary.Prefixes = normalizeStrings(value.Selectors.Binary.Prefixes)
	value.Selectors.Process.BinaryPrefixes = normalizeStrings(value.Selectors.Process.BinaryPrefixes)
	value.Selectors.File.Prefixes = normalizeStrings(value.Selectors.File.Prefixes)
	value.Selectors.File.PrefixRefs = normalizeStrings(value.Selectors.File.PrefixRefs)
	value.Selectors.Socket.Families = normalizeStrings(value.Selectors.Socket.Families)
	value.Selectors.Socket.Addrs = normalizeStrings(value.Selectors.Socket.Addrs)
	value.Selectors.Socket.AddrRefs = normalizeStrings(value.Selectors.Socket.AddrRefs)
	value.Selectors.Socket.Ports = normalizeStrings(value.Selectors.Socket.Ports)
	value.Selectors.Socket.PortRefs = normalizeStrings(value.Selectors.Socket.PortRefs)
}

func behaviorFilter(spec BehaviorPolicy) BehaviorFilter {
	return BehaviorFilter{Behavior: domainevent.NormalizeBehavior(spec.ID), BinaryPrefixes: normalizeStrings(append(clone(spec.Selectors.Binary.Prefixes), spec.Selectors.Process.BinaryPrefixes...)), FilePrefixes: clone(spec.Selectors.File.Prefixes), SocketFamilies: clone(spec.Selectors.Socket.Families), SocketAddrs: clone(spec.Selectors.Socket.Addrs), SocketPorts: clone(spec.Selectors.Socket.Ports)}
}

func flatBehaviorFilters(behaviors []string, value CollectionPolicy) []BehaviorFilter {
	result := make([]BehaviorFilter, 0, len(behaviors))
	for _, behavior := range behaviors {
		filter := BehaviorFilter{Behavior: behavior}
		if behavior == "process.exec" || behavior == "process.fork" || strings.HasPrefix(behavior, "file.") || behavior == "network.connect" {
			filter.BinaryPrefixes = clone(value.BinaryPrefixes)
		}
		if strings.HasPrefix(behavior, "file.") {
			filter.FilePrefixes = clone(value.FilePrefixes)
		}
		if behavior == "network.connect" {
			filter.SocketFamilies, filter.SocketAddrs, filter.SocketPorts = clone(value.SocketFamilies), clone(value.SocketAddrs), clone(value.SocketPorts)
		}
		result = append(result, filter)
	}
	return result
}

func lookupValueSet(snapshot ContentSnapshot, ref string) (ValueSet, bool) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "ctx:") {
		value, ok := snapshot.ContextSets[ref]
		return value, ok
	}
	if strings.HasPrefix(ref, "ioc:") {
		value, ok := snapshot.IOCPacks[ref]
		return value, ok
	}
	if value, ok := snapshot.ContextSets[ref]; ok {
		return value, true
	}
	value, ok := snapshot.IOCPacks[ref]
	return value, ok
}

func normalizeBehaviors(values []string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = domainevent.NormalizeBehavior(value)
	}
	return normalizeStrings(result)
}
func normalizeStrings(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func knownBehavior(value string) bool {
	switch value {
	case "process.exec", "process.exit", "process.fork", "file.open", "file.read", "file.write", "file.chmod", "network.connect":
		return true
	}
	return false
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func clone(values []string) []string { return append([]string(nil), values...) }

func cloneCollection(value CollectionPolicy) CollectionPolicy {
	value.Behaviors = clone(value.Behaviors)
	value.BinaryPrefixes = clone(value.BinaryPrefixes)
	value.FilePrefixes = clone(value.FilePrefixes)
	value.SocketFamilies = clone(value.SocketFamilies)
	value.SocketAddrs = clone(value.SocketAddrs)
	value.SocketPorts = clone(value.SocketPorts)
	value.BehaviorSpecs = cloneBehaviorPolicies(value.BehaviorSpecs)
	return value
}

func cloneBehaviorPolicies(values []BehaviorPolicy) []BehaviorPolicy {
	result := make([]BehaviorPolicy, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Enabled = cloneBool(value.Enabled)
		result[index].Selectors.Binary.Prefixes = clone(value.Selectors.Binary.Prefixes)
		result[index].Selectors.Process.BinaryPrefixes = clone(value.Selectors.Process.BinaryPrefixes)
		result[index].Selectors.File.Prefixes = clone(value.Selectors.File.Prefixes)
		result[index].Selectors.File.PrefixRefs = clone(value.Selectors.File.PrefixRefs)
		result[index].Selectors.Socket.Families = clone(value.Selectors.Socket.Families)
		result[index].Selectors.Socket.Addrs = clone(value.Selectors.Socket.Addrs)
		result[index].Selectors.Socket.AddrRefs = clone(value.Selectors.Socket.AddrRefs)
		result[index].Selectors.Socket.Ports = clone(value.Selectors.Socket.Ports)
		result[index].Selectors.Socket.PortRefs = clone(value.Selectors.Socket.PortRefs)
	}
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
