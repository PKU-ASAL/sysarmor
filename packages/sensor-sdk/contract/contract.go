package contract

import (
	"context"
	"fmt"
	"strings"
	"time"

	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
)

type ApplyState string

const (
	ApplyStateApplied  ApplyState = "applied"
	ApplyStateDeferred ApplyState = "deferred"
)

type ApplyResult struct {
	State ApplyState
}

type Sensor interface {
	Capability(ctx context.Context) (Capability, error)
	Apply(ctx context.Context, intent CollectionIntent) (ApplyResult, error)
	Subscribe(ctx context.Context, intent CollectionIntent) (<-chan EventEnvelope, error)
	Enforce(ctx context.Context, cmd EnforcementCmd) (EnforcementAck, error)
	Health(ctx context.Context) (Health, error)
}

type Capability struct {
	Backend         string
	Version         string
	SupportsExec    bool
	SupportsConnect bool
	SupportsFile    bool
	SupportsEnforce bool
	SupportsHealth  bool
	KernelRelease   string
	BTFAvailable    bool
	BPFFSAvailable  bool
	Collection      []CollectionBehaviorCapability
}

type CollectionIntent struct {
	Behaviors          []string
	MandatoryBehaviors []string
	BinaryPrefixes     []string
	FilePrefixes       []string
	FileWriteExcludes  []string
	SocketFamilies     []string
	SocketAddrs        []string
	SocketPorts        []string
	BehaviorFilters    []CollectionBehaviorFilter
	NamespaceSelectors []NamespaceSelector
	ScopeType          string
	ScopeSelector      string
	ObserveOnly        bool
	Capabilities       []CollectionBehaviorCapability
}

type CollectionBehaviorFilter struct {
	Behavior       string
	BinaryPrefixes []string
	FilePrefixes   []string
	SocketFamilies []string
	SocketAddrs    []string
	SocketPorts    []string
}

type NamespaceSelector struct {
	Namespace string
	Values    []string
}

type CollectionCompileReport struct {
	Status               string                     `json:"status"`
	Backend              string                     `json:"backend"`
	GeneratedPolicyHash  string                     `json:"generated_policy_hash,omitempty"`
	ResolvedRefs         []CollectionResolvedRef    `json:"resolved_refs,omitempty"`
	BehaviorMappings     []CollectionBehaviorMap    `json:"behavior_mappings,omitempty"`
	PushedDownSelectors  []CollectionSelectorReport `json:"pushed_down_selectors,omitempty"`
	AgentSideSelectors   []CollectionSelectorReport `json:"agent_side_selectors,omitempty"`
	UnsupportedSelectors []CollectionSelectorReport `json:"unsupported_selectors,omitempty"`
	Warnings             []string                   `json:"warnings,omitempty"`
}

type CollectionResolvedRef struct {
	Behavior  string   `json:"behavior,omitempty"`
	Selector  string   `json:"selector"`
	Ref       string   `json:"ref"`
	Version   string   `json:"version,omitempty"`
	Digest    string   `json:"digest,omitempty"`
	ValueType string   `json:"value_type,omitempty"`
	Count     int      `json:"count"`
	Values    []string `json:"values,omitempty"`
}

type CollectionBehaviorMap struct {
	Behavior string `json:"behavior"`
	Backend  string `json:"backend"`
	Hook     string `json:"hook"`
}

type CollectionSelectorReport struct {
	Behavior string `json:"behavior"`
	Selector string `json:"selector"`
	Status   string `json:"status"`
	Location string `json:"location"`
	Mapping  string `json:"mapping,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type CollectionBehaviorCapability struct {
	Behavior             string
	SensorMapping        string
	Fields               []string
	PushdownSelectors    []string
	AgentSideSelectors   []string
	UnsupportedSelectors []string
}

func NormalizeScope(scopeType, scopeSelector string) (string, string, error) {
	scopeType = strings.TrimSpace(scopeType)
	scopeSelector = strings.TrimSpace(scopeSelector)
	if scopeType == "" {
		scopeType = "host"
	}
	switch scopeType {
	case "host":
		if scopeSelector != "" {
			return "", "", fmt.Errorf("scope selector must be empty when scope type is host")
		}
	case "container", "cgroup", "namespace", "pod":
		if scopeSelector == "" {
			return "", "", fmt.Errorf("scope selector is required when scope type is %s", scopeType)
		}
	default:
		return "", "", fmt.Errorf("scope type must be one of host, container, cgroup, namespace, pod")
	}
	return scopeType, scopeSelector, nil
}

func ValidateScope(scopeType, scopeSelector string) error {
	_, _, err := NormalizeScope(scopeType, scopeSelector)
	return err
}

func (i CollectionIntent) NormalizeScope() (CollectionIntent, error) {
	scopeType, scopeSelector, err := NormalizeScope(i.ScopeType, i.ScopeSelector)
	if err != nil {
		return CollectionIntent{}, err
	}
	i.ScopeType = scopeType
	i.ScopeSelector = scopeSelector
	return i, nil
}

type EventEnvelope struct {
	SensorEvent *sensorv1.SensorEvent
	RawRef      string
	ReceivedAt  time.Time
}

type Health struct {
	Backend        string
	Running        bool
	Installed      bool
	Version        string
	PolicyLoaded   bool
	EventsSeen     uint64
	EventsDropped  uint64
	ParseErrors    uint64
	RestartCount   uint64
	LastEventAt    time.Time
	LastExitReason string
	LastError      string
}

type EnforcementCmd struct {
	ID          string
	Action      string
	Target      string
	ObserveOnly bool
	Reason      string
}

type EnforcementAck struct {
	ID          string
	Accepted    bool
	Unsupported bool
	ObserveOnly bool
	Message     string
}

func ObserveOnlyAck(cmd EnforcementCmd, message string) EnforcementAck {
	return EnforcementAck{
		ID:          cmd.ID,
		Accepted:    true,
		ObserveOnly: true,
		Message:     message,
	}
}

func UnsupportedAck(cmd EnforcementCmd, message string) EnforcementAck {
	return EnforcementAck{
		ID:          cmd.ID,
		Unsupported: true,
		Message:     message,
	}
}
