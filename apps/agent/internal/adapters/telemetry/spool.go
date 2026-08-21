package telemetry

import (
	"context"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanecontract "github.com/sysarmor/sysarmor-next-project/packages/contracts/dataplane"
	"google.golang.org/protobuf/proto"
)

type LocalSpool struct{ store *sqlite.Store }

func NewLocalSpool(store *sqlite.Store) *LocalSpool {
	return &LocalSpool{store: store}
}

func (spool *LocalSpool) Checkpoint(ctx context.Context) (domaintelemetry.Position, error) {
	if spool == nil || spool.store == nil {
		return domaintelemetry.Position{}, fmt.Errorf("telemetry spool is not configured")
	}
	checkpoint, err := spool.store.Checkpoint(ctx)
	return domaintelemetry.Position{SegmentID: checkpoint.SegmentID, RecordOffset: checkpoint.RecordOffset, BatchID: checkpoint.LastBatchID}, err
}

func (spool *LocalSpool) Read(ctx context.Context, fromSequence uint64, limit int) ([]domaintelemetry.StoredBatch, error) {
	if spool == nil || spool.store == nil {
		return nil, fmt.Errorf("telemetry spool is not configured")
	}
	stored, err := spool.store.ReadBatches(ctx, sqlite.ReadOptions{Limit: limit, FromSequence: fromSequence})
	if err != nil {
		return nil, err
	}
	out := make([]domaintelemetry.StoredBatch, 0, len(stored))
	for _, item := range stored {
		payload, err := proto.Marshal(item.Batch)
		if err != nil {
			return nil, fmt.Errorf("encode telemetry batch %s: %w", item.Position.BatchID, err)
		}
		header := item.Batch.GetHeader()
		out = append(out, domaintelemetry.StoredBatch{
			Position: domainPosition(item.Position),
			Batch: domaintelemetry.Batch{
				ID: header.GetBatchId(), TenantID: header.GetTenantId(), AgentID: header.GetAgentId(), Payload: payload,
				ModelCandidates: dataplanecontract.CountModelCandidates(item.Batch),
			},
		})
	}
	return out, nil
}

func (spool *LocalSpool) SaveCheckpoint(ctx context.Context, position domaintelemetry.Position) error {
	if spool == nil || spool.store == nil {
		return fmt.Errorf("telemetry spool is not configured")
	}
	return spool.store.SaveCheckpoint(ctx, sqlite.Checkpoint{
		SegmentID: position.SegmentID, RecordOffset: position.RecordOffset, LastBatchID: position.BatchID,
	})
}

func domainPosition(position sqlite.Position) domaintelemetry.Position {
	return domaintelemetry.Position{
		SegmentID: position.SegmentID, RecordOffset: position.RecordOffset,
		BatchSequence: position.BatchSequence, BatchID: position.BatchID,
	}
}
