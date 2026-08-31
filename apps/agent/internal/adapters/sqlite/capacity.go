package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type CapacityResult struct {
	RemovedSegments   []uint64
	RemovedBatches    uint64
	DroppedUnuploaded bool
}

type segmentCandidate struct {
	id       uint64
	path     string
	records  uint64
	uploaded bool
}

func (s *Store) EnforceCapacity(ctx context.Context) (CapacityResult, error) {
	if _, err := s.PruneSignals(ctx); err != nil {
		return CapacityResult{}, err
	}
	over, err := s.overCapacity()
	if err != nil || !over {
		return CapacityResult{}, err
	}
	candidates, err := s.capacityCandidates(ctx)
	if err != nil {
		return CapacityResult{}, err
	}
	var result CapacityResult
	for _, candidate := range candidates {
		if err := os.Remove(candidate.path); err != nil && !os.IsNotExist(err) {
			return result, err
		}
		if _, err := s.db.ExecContext(ctx, "DELETE FROM segments WHERE segment_id=?", candidate.id); err != nil {
			return result, err
		}
		result.RemovedSegments = append(result.RemovedSegments, candidate.id)
		if !candidate.uploaded {
			result.DroppedUnuploaded = true
			result.RemovedBatches += candidate.records
		}
		over, err = s.overCapacity()
		if err != nil || !over {
			break
		}
	}
	if result.DroppedUnuploaded {
		if counterErr := s.recordDroppedBatches(ctx, result.RemovedBatches); counterErr != nil {
			return result, counterErr
		}
	}
	return result, err
}

func (s *Store) capacityCandidates(ctx context.Context) ([]segmentCandidate, error) {
	checkpoint, err := s.LatestCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT segment_id,path,record_count FROM segments WHERE state='sealed' ORDER BY segment_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uploaded, pending []segmentCandidate
	for rows.Next() {
		var candidate segmentCandidate
		if err := rows.Scan(&candidate.id, &candidate.path, &candidate.records); err != nil {
			return nil, err
		}
		candidate.uploaded = checkpoint.SegmentID > candidate.id
		if candidate.uploaded {
			uploaded = append(uploaded, candidate)
		} else {
			pending = append(pending, candidate)
		}
	}
	return append(uploaded, pending...), rows.Err()
}

func (s *Store) overCapacity() (bool, error) {
	bytes, err := directoryBytes(s.rootDir)
	if err != nil {
		return false, err
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.rootDir, &stat); err != nil {
		return false, err
	}
	free := int64(stat.Bavail) * int64(stat.Bsize)
	return bytes > s.opts.MaxBytes || free < s.opts.MinFreeBytes, nil
}

func directoryBytes(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func (s *Store) recordDroppedBatches(ctx context.Context, count uint64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runtime_counters(singleton,dropped_batches_storage) VALUES(1,?)
ON CONFLICT(singleton) DO UPDATE SET dropped_batches_storage=dropped_batches_storage+excluded.dropped_batches_storage`, count)
	if err != nil {
		return fmt.Errorf("record storage drops: %w", err)
	}
	return nil
}
