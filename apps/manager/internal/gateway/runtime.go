package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	sessionapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway/session"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	platformkafka "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/kafka"
	platformredis "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/redis"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type Store interface {
	ControlStore
	BindAgentIdentity(store.AgentIdentity) error
	RecordDataBatchAppend(store.AgentIdentity, string, string, time.Time) store.AgentSession
}

type SessionApplication interface {
	Resume(context.Context, string, string) (sessionapp.ResumeResult, error)
	IsDuplicate(context.Context, string, string, string) (bool, error)
}

type Runtime struct {
	store          Store
	sessions       SessionApplication
	producer       platformkafka.Producer
	hotState       platformredis.HotState
	localProcessor *ingestworker.Processor
	agentToken     string
	owner          string
	metrics        Metrics
}

type RuntimeOptions struct {
	Store              Store
	Producer           platformkafka.Producer
	HotState           platformredis.HotState
	LocalProcessor     *ingestworker.Processor
	AgentToken         string
	Owner              string
	SessionApplication SessionApplication
}

func NewRuntime(opts RuntimeOptions) *Runtime {
	if opts.SessionApplication == nil {
		if memoryStore, ok := opts.Store.(*store.Store); ok {
			opts.SessionApplication = sessionapp.NewQueryService(store.NewSessionRepository(memoryStore))
		}
	}
	producer := opts.Producer
	if producer == nil {
		producer = platformkafka.NoopProducer{}
	}
	hotState := opts.HotState
	if hotState == nil {
		hotState = platformredis.NoopHotState{}
	}
	owner := opts.Owner
	if owner == "" {
		owner = "sysarmor-gateway"
	}
	return &Runtime{
		store:          opts.Store,
		sessions:       opts.SessionApplication,
		producer:       producer,
		hotState:       hotState,
		localProcessor: opts.LocalProcessor,
		agentToken:     opts.AgentToken,
		owner:          owner,
	}
}

func (r *Runtime) AgentToken() string {
	return r.agentToken
}

func (r *Runtime) Store() ControlStore {
	return r.store
}

func (r *Runtime) SessionApplication() SessionApplication { return r.sessions }

func (r *Runtime) BindAgentIdentity(agent store.AgentIdentity) error {
	return r.store.BindAgentIdentity(agent)
}

func (r *Runtime) TouchHotSession(session store.AgentSession) {
	if session.AgentID == "" {
		return
	}
	_ = r.hotState.TouchAgentSession(context.Background(), platformredis.AgentSession{
		TenantID:          session.TenantID,
		AgentID:           session.AgentID,
		Owner:             r.owner,
		LastSeenAt:        session.LastSeenAt,
		LastDataSeenAt:    session.LastDataSeenAt,
		LastControlSeenAt: session.LastControlSeenAt,
		LastAckCursor:     session.LastAckCursor,
		DataTransport:     session.DataTransport,
		ControlTransport:  session.ControlTransport,
	})
}

func (r *Runtime) ResumeCursor(tenantID, agentID string) (ResumeCursor, error) {
	resume := ResumeCursor{TenantID: tenantID, AgentID: agentID}
	resumeValue, err := r.sessions.Resume(context.Background(), tenantID, agentID)
	if err != nil {
		return ResumeCursor{}, err
	}
	resume.SessionID, resume.ResumeCursor = resumeValue.SessionID, resumeValue.Cursor
	return resume, nil
}

func (r *Runtime) AppendDataBatchWithTransport(batch *dataplanev1.DataBatch, transport string) (DataAppendResult, error) {
	if err := validateUploadIdentity(batch); err != nil {
		r.metrics.rejectedBatches.Add(1)
		return DataAppendResult{}, err
	}
	header := batch.GetHeader()
	duplicate, err := r.isDuplicateBatch(header.GetTenantId(), header.GetAgentId(), header.GetBatchId())
	if err != nil {
		return DataAppendResult{}, err
	}
	if duplicate {
		session := r.store.RecordDataBatchAppend(store.AgentIdentityFromDataBatch(batch), header.GetBatchId(), transport, time.Now().UTC())
		r.TouchHotSession(session)
		r.metrics.duplicateBatches.Add(1)
		return DataAppendResult{Duplicate: true}, r.store.Save()
	}
	if err := r.appendRawBatch(batch); err != nil {
		r.metrics.handoffErrors.Add(1)
		return DataAppendResult{}, err
	}
	session := r.store.RecordDataBatchAppend(store.AgentIdentityFromDataBatch(batch), header.GetBatchId(), transport, time.Now().UTC())
	r.TouchHotSession(session)
	if err := r.store.Save(); err != nil {
		return DataAppendResult{}, err
	}
	result, err := r.processLocal(batch)
	if err != nil {
		r.metrics.rejectedBatches.Add(1)
		return DataAppendResult{}, err
	}
	r.metrics.acceptedBatches.Add(1)
	r.metrics.acceptedEvents.Add(uint64(result.AcceptedEvents))
	r.metrics.acceptedSignals.Add(uint64(result.AcceptedSignals))
	return result, nil
}

func (r *Runtime) appendRawBatch(batch *dataplanev1.DataBatch) error {
	raw, err := protojson.Marshal(batch)
	if err != nil {
		return fmt.Errorf("encode raw data batch: %w", err)
	}
	header := batch.GetHeader()
	key := strings.Join([]string{header.GetTenantId(), batchCorrelationKey(batch)}, ":")
	return r.producer.Append(context.Background(), platformkafka.Message{Topic: "sysarmor.agent.databatch.raw", Key: key, Value: raw})
}

func batchCorrelationKey(batch *dataplanev1.DataBatch) string {
	for _, labels := range batchScopeLabels(batch) {
		for _, key := range []string{"case_type", "scenario", "workload"} {
			if value := strings.TrimSpace(labels[key]); value != "" {
				return key + "=" + value
			}
		}
	}
	return batch.GetHeader().GetAgentId()
}

func batchScopeLabels(batch *dataplanev1.DataBatch) []map[string]string {
	labels := []map[string]string{batch.GetHeader().GetLabels()}
	for _, frame := range batch.GetEvents() {
		labels = append(labels, frame.GetEvent().GetLabels())
	}
	for _, frame := range batch.GetSignals() {
		labels = append(labels, frame.GetSignal().GetLabels())
	}
	return labels
}

func (r *Runtime) processLocal(batch *dataplanev1.DataBatch) (DataAppendResult, error) {
	if r.localProcessor == nil {
		return DataAppendResult{}, nil
	}
	result, err := r.localProcessor.Process(context.Background(), batch)
	if err != nil {
		return DataAppendResult{}, err
	}
	return DataAppendResult{
		AcceptedEvents:  result.AcceptedEvents,
		AcceptedSignals: result.AcceptedSignals,
		CloudSignals:    result.CloudSignals,
		Incidents:       result.Incidents,
	}, nil
}

func (r *Runtime) isDuplicateBatch(tenantID, agentID, batchID string) (bool, error) {
	if batchID == "" {
		return false, nil
	}
	duplicate, err := r.sessions.IsDuplicate(context.Background(), tenantID, agentID, batchID)
	if err != nil {
		return false, fmt.Errorf("list agent sessions: %w", err)
	}
	return duplicate, nil
}

func validateUploadIdentity(batch *dataplanev1.DataBatch) error {
	if batch == nil || batch.GetHeader() == nil {
		return fmt.Errorf("%w: batch header identity is required", ErrInvalidUpload)
	}
	header := batch.GetHeader()
	missing := []string{}
	if header.GetAgentId() == "" {
		missing = append(missing, "agent_id")
	}
	if header.GetHostId() == "" {
		missing = append(missing, "host_id")
	}
	if header.GetTenantId() == "" {
		missing = append(missing, "tenant_id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: agent identity missing %s", ErrInvalidUpload, strings.Join(missing, ", "))
	}
	return nil
}

func (r *Runtime) MetricsSnapshot() MetricsSnapshot {
	return r.metrics.Snapshot()
}
