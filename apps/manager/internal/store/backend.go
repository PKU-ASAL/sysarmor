package store

import (
	"context"
	"errors"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection/rarity"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

var ErrConflict = errors.New("store conflict")

// Backend is the durable persistence boundary for platform state. A nil Backend
// means the Store is a pure in-memory/file store. Telemetry (events and signals)
// is intentionally excluded: high-volume telemetry belongs in the search/index
// tier (OpenSearch) and the in-process working set, not the relational state
// store. The Backend only persists low-volume, relational platform state.
type Backend interface {
	SaveState(ctx context.Context, state State) error

	ListAgents(ctx context.Context) ([]AgentIdentity, error)
	ListAgentHealth(ctx context.Context, tenantID string) ([]agenthealth.AgentHealth, error)
	GetAgentHealth(ctx context.Context, tenantID, agentID string) (agenthealth.AgentHealth, bool, error)
	ListAgentSessions(ctx context.Context, tenantID, agentID string) ([]AgentSession, error)
	ListResponses(ctx context.Context, tenantID, agentID string) ([]responsemodel.AuditRecord, error)
	ListEvidencePullbacks(ctx context.Context, tenantID, agentID string) ([]controlmodel.EvidencePullbackRequest, error)
	ListControlCommands(ctx context.Context, tenantID, agentID, commandType string) ([]controlmodel.ControlCommand, error)
	ListPolicies(ctx context.Context, tenantID string) ([]policymodel.Policy, error)
	ListAssignments(ctx context.Context, tenantID, agentID string) ([]policymodel.Assignment, error)
	ListPolicyAudits(ctx context.Context, tenantID, policyID string) ([]policymodel.AuditRecord, error)
	GetPolicy(ctx context.Context, tenantID, policyID string, version uint64) (policymodel.Policy, bool, error)
	EffectivePolicy(ctx context.Context, tenantID, agentID, scopeType, scopeSelector string) (policymodel.Policy, bool, error)
	ListArtifacts(ctx context.Context, tenantID, kind, status string) ([]Artifact, error)
	GetArtifact(ctx context.Context, tenantID, artifactID string) (Artifact, bool, error)
	ListChannels(ctx context.Context, tenantID string) ([]ArtifactChannel, error)
	GetChannel(ctx context.Context, tenantID, channel string) (ArtifactChannel, bool, error)

	CreateResponse(ctx context.Context, cmd responsemodel.Command) (bool, error)
	WriteResponse(ctx context.Context, cmd responsemodel.Command, ack *responsemodel.Ack) error
	CreateControlCommand(ctx context.Context, cmd controlmodel.ControlCommand) (bool, error)
	WriteControlCommand(ctx context.Context, cmd controlmodel.ControlCommand) error
	WritePolicy(ctx context.Context, policy policymodel.Policy) error
	WriteAssignment(ctx context.Context, assignment policymodel.Assignment) error
	WritePolicyAudit(ctx context.Context, audit policymodel.AuditRecord) error
	CommitPolicyPublication(ctx context.Context, policy policymodel.Policy, audit policymodel.AuditRecord) error
	CommitPolicyAssignment(ctx context.Context, assignment policymodel.Assignment, audit policymodel.AuditRecord, command *controlmodel.ControlCommand) (*controlmodel.ControlCommand, error)
	WriteArtifact(ctx context.Context, artifact Artifact) error
	WriteChannel(ctx context.Context, channel ArtifactChannel) error
}

type TenantMetricsBackend interface {
	LoadMetricsForTenant(ctx context.Context, tenantID string) (Metrics, error)
}

type TenantRarityBackend interface {
	LoadRarityForTenant(ctx context.Context, tenantID string) (rarity.Baseline, error)
}

type BatchClaim int

const (
	BatchClaimed BatchClaim = iota
	BatchDuplicate
	BatchBusy
)

type TelemetryBatchDelta struct {
	TenantID   string
	BatchID    string
	ClaimToken string
	Metrics    Metrics
	Rarity     rarity.Baseline
}

type TelemetryBatchBackend interface {
	ClaimTelemetryBatch(ctx context.Context, tenantID, batchID, claimToken string, leaseDuration time.Duration) (BatchClaim, error)
	CommitTelemetryBatch(ctx context.Context, delta TelemetryBatchDelta) error
	AbandonTelemetryBatch(ctx context.Context, tenantID, batchID, claimToken string) error
}
