package store

import (
	"encoding/json"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

const FileStoreStateVersion = 1

type LabelSelector map[string]string

func LabelsMatch(labels map[string]string, selector LabelSelector) bool {
	return labelSelectorMatches(labels, selector)
}

type Info struct {
	Backend          string `json:"backend"`
	Path             string `json:"path,omitempty"`
	StateVersion     int    `json:"state_version"`
	MigrationVersion int    `json:"migration_version"`
	PostgresSchema   int    `json:"postgres_schema_version"`
}

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

type TelemetryBatchRecord struct {
	TenantID    string    `json:"tenant_id"`
	BatchID     string    `json:"batch_id"`
	Status      string    `json:"status"`
	ClaimToken  string    `json:"claim_token"`
	LeaseUntil  time.Time `json:"lease_until"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type AgentSession struct {
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

type ArtifactChannel struct {
	TenantID   string    `json:"tenant_id"`
	Channel    string    `json:"channel"`
	ArtifactID string    `json:"artifact_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CreatedBy  string    `json:"created_by,omitempty"`
}

type Artifact struct {
	ArtifactID  string            `json:"artifact_id"`
	TenantID    string            `json:"tenant_id"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Version     string            `json:"version"`
	OS          string            `json:"os,omitempty"`
	Arch        string            `json:"arch,omitempty"`
	SHA256      string            `json:"sha256"`
	SizeBytes   int64             `json:"size_bytes"`
	Status      string            `json:"status"`
	StoragePath string            `json:"storage_path,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type State struct {
	Agents           []json.RawMessage                      `json:"agents"`
	Events           []json.RawMessage                      `json:"events"`
	Signals          []json.RawMessage                      `json:"signals"`
	Incidents        []json.RawMessage                      `json:"incidents"`
	Health           []json.RawMessage                      `json:"health"`
	Rules            []policymodel.RuleContent              `json:"rules"`
	Policies         []policymodel.Policy                   `json:"policies"`
	Assignments      []policymodel.Assignment               `json:"assignments"`
	PolicyAudits     []policymodel.AuditRecord              `json:"policy_audits"`
	Responses        []responsemodel.Command                `json:"responses"`
	ResponseAcks     []responsemodel.Ack                    `json:"response_acks"`
	Pullbacks        []controlmodel.EvidencePullbackRequest `json:"evidence_pullbacks"`
	ControlCommands  []controlmodel.ControlCommand          `json:"control_commands,omitempty"`
	AgentSessions    []AgentSession                         `json:"agent_sessions"`
	Artifacts        []Artifact                             `json:"artifacts,omitempty"`
	Channels         []ArtifactChannel                      `json:"channels,omitempty"`
	TenantSignals    map[string][]json.RawMessage           `json:"tenant_signals,omitempty"`
	MetricsByTenant  map[string]Metrics                     `json:"metrics_by_tenant,omitempty"`
	RarityByTenant   map[string]rarity.Baseline             `json:"rarity_by_tenant,omitempty"`
	TelemetryBatches map[string]TelemetryBatchRecord        `json:"telemetry_batches,omitempty"`
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
