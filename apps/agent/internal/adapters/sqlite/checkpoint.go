package sqlite

import (
	"context"
	"database/sql"
	"time"
)

type Checkpoint struct {
	SegmentID    uint64
	RecordOffset int64
	LastBatchID  string
	UpdatedAt    time.Time
}

func (s *Store) SaveCheckpoint(ctx context.Context, checkpoint Checkpoint) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO upload_checkpoint(singleton,segment_id,record_offset,last_batch_id,updated_at_ns)
VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET segment_id=excluded.segment_id,record_offset=excluded.record_offset,last_batch_id=excluded.last_batch_id,updated_at_ns=excluded.updated_at_ns`,
		checkpoint.SegmentID, checkpoint.RecordOffset, checkpoint.LastBatchID, now.UnixNano())
	return err
}

func (s *Store) Checkpoint(ctx context.Context) (Checkpoint, error) {
	var checkpoint Checkpoint
	var updatedAt int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(segment_id,0),record_offset,COALESCE(last_batch_id,''),updated_at_ns FROM upload_checkpoint WHERE singleton=1`).Scan(
		&checkpoint.SegmentID, &checkpoint.RecordOffset, &checkpoint.LastBatchID, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return Checkpoint{}, nil
	}
	checkpoint.UpdatedAt = time.Unix(0, updatedAt).UTC()
	return checkpoint, err
}
