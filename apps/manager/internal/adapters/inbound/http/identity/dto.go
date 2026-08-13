package identity

import (
	"encoding/json"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

type agentItem struct {
	AgentID, HostID, TenantID       string
	Version, AuthType, CertIdentity string
	HealthStatus                    string
	Scope                           domainidentity.Scope
	Capability                      json.RawMessage
	HealthObserved                  time.Time
}

type sessionDTO struct {
	SessionID         string    `json:"session_id"`
	TenantID          string    `json:"tenant_id"`
	AgentID           string    `json:"agent_id"`
	StartedAt         time.Time `json:"started_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	LastDataSeenAt    time.Time `json:"last_data_seen_at,omitempty"`
	LastControlSeenAt time.Time `json:"last_control_seen_at,omitempty"`
	ClosedAt          time.Time `json:"closed_at,omitempty"`
	LastAckCursor     string    `json:"last_ack_cursor,omitempty"`
	DataTransport     string    `json:"data_transport,omitempty"`
	ControlTransport  string    `json:"control_transport,omitempty"`
	Status            string    `json:"status,omitempty"`
}

type metricsDTO struct {
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

type resumeDTO struct {
	TenantID     string `json:"tenant_id"`
	AgentID      string `json:"agent_id"`
	SessionID    string `json:"session_id,omitempty"`
	ResumeCursor string `json:"resume_cursor,omitempty"`
}
