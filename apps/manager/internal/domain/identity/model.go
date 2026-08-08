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

type Scope struct{ Type, Selector string }

type Health struct {
	TenantID   tenant.ID
	AgentID    AgentID
	HostID     string
	Status     string
	Scope      Scope
	ObservedAt time.Time
	Document   []byte
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
	DataBatchesAppended, EventsIngested, EndpointSignalsIngested uint64
	CloudSignalsEmitted, SignalsEmitted, IncidentsCreated        uint64
	DroppedEvents, DuplicateEvents                               uint64
	LastConvergenceLatencyMs, MaxConvergenceLatencyMs            uint64
	TotalConvergenceLatencyMs                                    uint64
	AverageConvergenceLatency                                    float64
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
