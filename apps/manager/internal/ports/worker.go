package ports

import (
	"context"
	"time"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type RawMessage struct {
	Topic, Key string
	Partition  int
	Offset     int64
	Value      []byte
}

type RawConsumer interface {
	Fetch(context.Context) (RawMessage, error)
	Commit(context.Context, RawMessage) error
}

type RawProducer interface {
	Publish(context.Context, RawMessage) error
}

type BatchProcessor interface {
	Process(context.Context, RawMessage) error
}

type RarityReader interface {
	Rarity(context.Context, tenant.ID) (identity.RarityBaseline, error)
}

type HistorySnapshot struct {
	Events  []domaintelemetry.Event
	Signals []ObservedSignal
}

type HistoryReader interface {
	Read(context.Context, tenant.ID, map[string]string, time.Time, time.Time) (HistorySnapshot, error)
}

type SearchDocument struct {
	Index string
	ID    string
	Body  []byte
}

type DocumentProjector interface {
	BulkIndex(context.Context, []SearchDocument) error
}

type NoopDocumentProjector struct{}

func (NoopDocumentProjector) BulkIndex(context.Context, []SearchDocument) error { return nil }

type TelemetryClaim int

const (
	TelemetryClaimed TelemetryClaim = iota
	TelemetryDuplicate
	TelemetryBusy
)

type TelemetryMetrics struct {
	DataBatches, Events, EndpointSignals, CloudSignals  uint64
	Signals, Incidents                                  uint64
	ModelCandidatesCorrelated, ModelCandidatesProjected uint64
	ModelCandidatesReferenceRejected                    uint64
	LastLatencyMs, MaxLatencyMs, TotalLatencyMs         uint64
	AverageLatencyMs                                    float64
}

type TelemetryBatchDelta struct {
	TenantID, BatchID, ClaimToken string
	Metrics                       TelemetryMetrics
	Rarity                        identity.RarityBaseline
	ProjectedSignals              []SignalProcessingRecord
}

type SignalProcessingRecord struct {
	SignalID, SubjectID, TriggerEventID string
	EventSequence                       uint64
}

type SignalProcessingBatch struct {
	TenantID, AgentID, BatchID, ClaimToken string
	Signals                                []SignalProcessingRecord
}

type TelemetryBatches interface {
	Claim(context.Context, string, string, time.Duration) (TelemetryClaim, string, error)
	Renew(context.Context, string, string, string, time.Duration) error
	Commit(context.Context, TelemetryBatchDelta) error
	Abandon(context.Context, string, string, string) error
	CorrelateSignals(context.Context, SignalProcessingBatch) error
}

type DetectionPolicyReader interface {
	Published(context.Context, tenant.ID, domainpolicy.ID, domainpolicy.Version) (domaindetection.Policy, error)
}

type PermanentError struct {
	Err                error
	Message            *RawMessage
	CandidateRejection *CandidateRejection
}

func (err PermanentError) Error() string { return err.Err.Error() }
func (err PermanentError) Unwrap() error { return err.Err }

type CandidateRejection struct {
	TenantID, AgentID, BatchID, FailureClass string
	Signals                                  []RejectedSignal
}

type RejectedSignal struct {
	SignalID      string
	EventSequence *uint64
}

type CandidateRejectionRecorder interface {
	RecordCandidateRejection(context.Context, CandidateRejection) error
}
