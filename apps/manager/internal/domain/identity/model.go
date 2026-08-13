package identity

import (
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type AgentID string

type Agent struct {
	TenantID            tenant.ID
	ID                  AgentID
	HostID              string
	Version             string
	AuthType            string
	CertificateIdentity string
}

type AgentFilter struct {
	ScopeType, ScopeSelector, HealthStatus string
}

type AgentView struct {
	Agent     Agent
	Health    Health
	HasHealth bool
}

type Scope struct{ Type, Selector string }

type PolicyRef struct {
	ID      string
	Version uint64
}

type PendingPolicy struct {
	Status, Source, ID, Digest string
	Version                    uint64
}

type Health struct {
	TenantID      tenant.ID
	AgentID       AgentID
	HostID        string
	Status        string
	Scope         Scope
	ObservedAt    time.Time
	ReportedAt    time.Time
	Document      []byte
	AppliedPolicy PolicyRef
	PendingPolicy PendingPolicy
}

func (value Health) Clone() Health {
	value.Document = append([]byte(nil), value.Document...)
	return value
}

type HealthFilter struct{ AgentID string }

type Session struct {
	TenantID                          tenant.ID
	ID                                string
	AgentID                           AgentID
	StartedAt, LastSeenAt             time.Time
	LastDataSeenAt, LastControlSeenAt time.Time
	ClosedAt                          time.Time
	LastAckCursor, DataTransport      string
	ControlTransport, Status          string
}

type SessionFilter struct{ AgentID string }

type Metrics struct {
	DataBatchesAppended       uint64  `json:"data_batches_appended"`
	EventsIngested            uint64  `json:"events_ingested"`
	EndpointSignalsIngested   uint64  `json:"endpoint_signals_ingested"`
	CloudSignalsEmitted       uint64  `json:"cloud_signals_emitted"`
	SignalsEmitted            uint64  `json:"signals_emitted"`
	IncidentsCreated          uint64  `json:"incidents_created"`
	DroppedEvents             uint64  `json:"dropped_events"`
	DuplicateEvents           uint64  `json:"duplicate_events"`
	LastConvergenceLatencyMs  uint64  `json:"last_convergence_latency_ms"`
	MaxConvergenceLatencyMs   uint64  `json:"max_convergence_latency_ms"`
	TotalConvergenceLatencyMs uint64  `json:"total_convergence_latency_ms"`
	AverageConvergenceLatency float64 `json:"average_convergence_latency_ms"`
}

type RarityBaseline struct {
	WorkloadCounts map[string]map[string]uint64
	Document       []byte
}

func (value RarityBaseline) Count(workload, signal string) uint64 {
	if signals := value.WorkloadCounts[workload]; signals != nil && signals[signal] > 0 {
		return signals[signal]
	}
	return value.WorkloadCounts["global"][signal]
}

func (value RarityBaseline) Clone() RarityBaseline {
	clone := RarityBaseline{Document: append([]byte(nil), value.Document...), WorkloadCounts: map[string]map[string]uint64{}}
	for workload, signals := range value.WorkloadCounts {
		clone.WorkloadCounts[workload] = map[string]uint64{}
		for signal, count := range signals {
			clone.WorkloadCounts[workload][signal] = count
		}
	}
	return clone
}

type AgentOverview struct{ Total, Online, Degraded, Offline int }

func MatchesAgentFilter(agent Agent, health Health, filter AgentFilter) bool {
	return (filter.ScopeType == "" || health.Scope.Type == filter.ScopeType) &&
		(filter.ScopeSelector == "" || health.Scope.Selector == filter.ScopeSelector) &&
		(filter.HealthStatus == "" || health.Status == filter.HealthStatus) &&
		strings.TrimSpace(string(agent.ID)) != ""
}
