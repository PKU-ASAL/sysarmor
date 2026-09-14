package sqlite

import (
	"context"
	"database/sql"
)

type Stats struct {
	StorageBytes          int64
	StorageMaxBytes       int64
	SignalCount           uint64
	SealedSegmentCount    uint64
	OpenSegmentBytes      int64
	OldestEventSequence   uint64
	LatestEventSequence   uint64
	DroppedBatchesStorage uint64
	DroppedEventsStorage  uint64
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	stats := Stats{StorageMaxBytes: s.opts.MaxBytes}
	bytes, err := directoryBytes(s.rootDir)
	if err != nil {
		return Stats{}, err
	}
	stats.StorageBytes = bytes
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM signals").Scan(&stats.SignalCount); err != nil {
		return Stats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM segments WHERE state='sealed'").Scan(&stats.SealedSegmentCount); err != nil {
		return Stats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(bytes),0) FROM segments WHERE state='open'").Scan(&stats.OpenSegmentBytes); err != nil {
		return Stats{}, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MIN(first_sequence),0),COALESCE(MAX(last_sequence),0) FROM segments").Scan(&stats.OldestEventSequence, &stats.LatestEventSequence); err != nil {
		return Stats{}, err
	}
	cursor, err := s.SequenceCursor(ctx)
	if err != nil {
		return Stats{}, err
	}
	stats.LatestEventSequence = cursor.Event
	err = s.db.QueryRowContext(ctx, `SELECT dropped_batches_storage,dropped_events_storage FROM runtime_counters WHERE singleton=1`).Scan(
		&stats.DroppedBatchesStorage, &stats.DroppedEventsStorage,
	)
	if err != nil && err != sql.ErrNoRows {
		return Stats{}, err
	}
	return stats, nil
}
