package policy

import (
	"encoding/json"
	"fmt"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

type collectionWire struct {
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

type behaviorWire struct {
	ID        string                `json:"id"`
	Enabled   *bool                 `json:"enabled,omitempty"`
	Selectors behaviorSelectorsWire `json:"selectors,omitempty"`
}

type behaviorSelectorsWire struct {
	Binary  binarySelectorWire  `json:"binary,omitempty"`
	Process processSelectorWire `json:"process,omitempty"`
	File    fileSelectorWire    `json:"file,omitempty"`
	Socket  socketSelectorWire  `json:"socket,omitempty"`
}

type binarySelectorWire struct {
	Prefixes []string `json:"prefixes,omitempty"`
}
type processSelectorWire struct {
	BinaryPrefixes []string `json:"binary_prefixes,omitempty"`
}
type fileSelectorWire struct {
	Prefixes   []string `json:"prefixes,omitempty"`
	PrefixRefs []string `json:"prefix_refs,omitempty"`
}
type socketSelectorWire struct {
	Families []string `json:"families,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
	AddrRefs []string `json:"addr_refs,omitempty"`
	Ports    []string `json:"ports,omitempty"`
	PortRefs []string `json:"port_refs,omitempty"`
}

func decodeCollectionDocument(data []byte) (domainpolicy.CollectionPolicy, error) {
	var wire collectionWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return domainpolicy.CollectionPolicy{}, fmt.Errorf("decode collection policy: %w", err)
	}
	value := domainpolicy.CollectionPolicy{
		Identity:       domainpolicy.Identity{ID: wire.PolicyID, Version: wire.Version},
		BinaryPrefixes: wire.BinaryPrefixes, FilePrefixes: wire.FilePrefixes,
		SocketFamilies: wire.SocketFamilies, SocketAddrs: wire.SocketAddrs,
		SocketPorts: wire.SocketPorts, ScopeType: wire.ScopeType,
		ScopeSelector: wire.ScopeSelector, ObserveOnly: wire.ObserveOnly,
	}
	if err := decodeCollectionBehaviors(wire.Behaviors, &value); err != nil {
		return domainpolicy.CollectionPolicy{}, err
	}
	return value, nil
}

func decodeCollectionBehaviors(raw json.RawMessage, value *domainpolicy.CollectionPolicy) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, &value.Behaviors); err == nil {
		return nil
	}
	var wires []behaviorWire
	if err := json.Unmarshal(raw, &wires); err != nil {
		return fmt.Errorf("decode collection behaviors: %w", err)
	}
	for _, wire := range wires {
		value.BehaviorSpecs = append(value.BehaviorSpecs, domainBehavior(wire))
	}
	return nil
}

func encodeCollectionDocument(value domainpolicy.CollectionPolicy) ([]byte, error) {
	wire := collectionWire{
		PolicyID: value.Identity.ID, Version: value.Identity.Version,
		BinaryPrefixes: value.BinaryPrefixes, FilePrefixes: value.FilePrefixes,
		SocketFamilies: value.SocketFamilies, SocketAddrs: value.SocketAddrs,
		SocketPorts: value.SocketPorts, ScopeType: value.ScopeType,
		ScopeSelector: value.ScopeSelector, ObserveOnly: value.ObserveOnly,
	}
	var err error
	if len(value.BehaviorSpecs) > 0 {
		behaviors := make([]behaviorWire, 0, len(value.BehaviorSpecs))
		for _, spec := range value.BehaviorSpecs {
			behaviors = append(behaviors, wireBehavior(spec))
		}
		wire.Behaviors, err = json.Marshal(behaviors)
	} else if len(value.Behaviors) > 0 {
		wire.Behaviors, err = json.Marshal(value.Behaviors)
	}
	if err != nil {
		return nil, fmt.Errorf("encode collection behaviors: %w", err)
	}
	return json.Marshal(wire)
}

func domainBehavior(value behaviorWire) domainpolicy.BehaviorPolicy {
	selectors := value.Selectors
	return domainpolicy.BehaviorPolicy{ID: value.ID, Enabled: value.Enabled, Selectors: domainpolicy.BehaviorSelectors{
		Binary:  domainpolicy.BinarySelector{Prefixes: selectors.Binary.Prefixes},
		Process: domainpolicy.ProcessSelector{BinaryPrefixes: selectors.Process.BinaryPrefixes},
		File:    domainpolicy.FileSelector{Prefixes: selectors.File.Prefixes, PrefixRefs: selectors.File.PrefixRefs},
		Socket:  domainpolicy.SocketSelector{Families: selectors.Socket.Families, Addrs: selectors.Socket.Addrs, AddrRefs: selectors.Socket.AddrRefs, Ports: selectors.Socket.Ports, PortRefs: selectors.Socket.PortRefs},
	}}
}

func wireBehavior(value domainpolicy.BehaviorPolicy) behaviorWire {
	selectors := value.Selectors
	return behaviorWire{ID: value.ID, Enabled: value.Enabled, Selectors: behaviorSelectorsWire{
		Binary:  binarySelectorWire{Prefixes: selectors.Binary.Prefixes},
		Process: processSelectorWire{BinaryPrefixes: selectors.Process.BinaryPrefixes},
		File:    fileSelectorWire{Prefixes: selectors.File.Prefixes, PrefixRefs: selectors.File.PrefixRefs},
		Socket:  socketSelectorWire{Families: selectors.Socket.Families, Addrs: selectors.Socket.Addrs, AddrRefs: selectors.Socket.AddrRefs, Ports: selectors.Socket.Ports, PortRefs: selectors.Socket.PortRefs},
	}}
}
