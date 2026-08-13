package contracts

import (
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	sharedpolicy "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func DomainCollectionPolicy(value sharedpolicy.CollectionPolicy) domainpolicy.CollectionPolicy {
	return domainpolicy.CollectionPolicy{
		Identity:       domainpolicy.Identity{ID: value.PolicyID, Version: value.Version},
		Behaviors:      cloneStrings(value.Behaviors),
		BehaviorSpecs:  domainBehaviorPolicies(value.BehaviorSpecs),
		BinaryPrefixes: cloneStrings(value.BinaryPrefixes),
		FilePrefixes:   cloneStrings(value.FilePrefixes),
		SocketFamilies: cloneStrings(value.SocketFamilies),
		SocketAddrs:    cloneStrings(value.SocketAddrs),
		SocketPorts:    cloneStrings(value.SocketPorts),
		ScopeType:      value.ScopeType,
		ScopeSelector:  value.ScopeSelector,
		ObserveOnly:    value.ObserveOnly,
	}
}

func SharedCollectionPolicy(value domainpolicy.CollectionPolicy) sharedpolicy.CollectionPolicy {
	return sharedpolicy.CollectionPolicy{
		PolicyID:       value.Identity.ID,
		Version:        value.Identity.Version,
		Behaviors:      cloneStrings(value.Behaviors),
		BehaviorSpecs:  sharedBehaviorPolicies(value.BehaviorSpecs),
		BinaryPrefixes: cloneStrings(value.BinaryPrefixes),
		FilePrefixes:   cloneStrings(value.FilePrefixes),
		SocketFamilies: cloneStrings(value.SocketFamilies),
		SocketAddrs:    cloneStrings(value.SocketAddrs),
		SocketPorts:    cloneStrings(value.SocketPorts),
		ScopeType:      value.ScopeType,
		ScopeSelector:  value.ScopeSelector,
		ObserveOnly:    value.ObserveOnly,
	}
}

func domainBehaviorPolicies(values []sharedpolicy.CollectionBehaviorPolicy) []domainpolicy.BehaviorPolicy {
	result := make([]domainpolicy.BehaviorPolicy, 0, len(values))
	for _, value := range values {
		result = append(result, domainpolicy.BehaviorPolicy{ID: value.ID, Enabled: cloneBool(value.Enabled), Selectors: domainpolicy.BehaviorSelectors{
			Binary:  domainpolicy.BinarySelector{Prefixes: cloneStrings(value.Selectors.Binary.Prefixes)},
			Process: domainpolicy.ProcessSelector{BinaryPrefixes: cloneStrings(value.Selectors.Process.BinaryPrefixes)},
			File:    domainpolicy.FileSelector{Prefixes: cloneStrings(value.Selectors.File.Prefixes), PrefixRefs: cloneStrings(value.Selectors.File.PrefixRefs)},
			Socket:  domainpolicy.SocketSelector{Families: cloneStrings(value.Selectors.Socket.Families), Addrs: cloneStrings(value.Selectors.Socket.Addrs), AddrRefs: cloneStrings(value.Selectors.Socket.AddrRefs), Ports: cloneStrings(value.Selectors.Socket.Ports), PortRefs: cloneStrings(value.Selectors.Socket.PortRefs)},
		}})
	}
	return result
}

func sharedBehaviorPolicies(values []domainpolicy.BehaviorPolicy) []sharedpolicy.CollectionBehaviorPolicy {
	result := make([]sharedpolicy.CollectionBehaviorPolicy, 0, len(values))
	for _, value := range values {
		result = append(result, sharedpolicy.CollectionBehaviorPolicy{ID: value.ID, Enabled: cloneBool(value.Enabled), Selectors: sharedpolicy.CollectionBehaviorSelectors{
			Binary:  sharedpolicy.BinarySelector{Prefixes: cloneStrings(value.Selectors.Binary.Prefixes)},
			Process: sharedpolicy.ProcessSelector{BinaryPrefixes: cloneStrings(value.Selectors.Process.BinaryPrefixes)},
			File:    sharedpolicy.FileSelector{Prefixes: cloneStrings(value.Selectors.File.Prefixes), PrefixRefs: cloneStrings(value.Selectors.File.PrefixRefs)},
			Socket:  sharedpolicy.SocketSelector{Families: cloneStrings(value.Selectors.Socket.Families), Addrs: cloneStrings(value.Selectors.Socket.Addrs), AddrRefs: cloneStrings(value.Selectors.Socket.AddrRefs), Ports: cloneStrings(value.Selectors.Socket.Ports), PortRefs: cloneStrings(value.Selectors.Socket.PortRefs)},
		}})
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

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
