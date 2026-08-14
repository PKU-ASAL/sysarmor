package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type Position struct {
	SegmentID     uint64
	RecordOffset  int64
	BatchSequence uint64
	BatchID       string
}

type segmentWriter struct {
	file          *os.File
	id            uint64
	path          string
	size          int64
	records       uint64
	firstSequence uint64
	lastSequence  uint64
}

func (s *Store) AppendBatch(ctx context.Context, batch *dataplanev1.DataBatch) (Position, error) {
	if batch == nil || batch.GetHeader().GetBatchId() == "" {
		return Position{}, fmt.Errorf("data batch and batch id are required")
	}
	record, sequence, err := encodeRecord(batch)
	if err != nil {
		return Position{}, err
	}
	s.segmentMu.Lock()
	defer s.segmentMu.Unlock()
	if position, ok := s.batchPositions[batch.GetHeader().GetBatchId()]; ok {
		return position, nil
	}
	if err := s.ensureWriter(ctx); err != nil {
		return Position{}, err
	}
	if s.writer.records > 0 && s.writer.size+int64(len(record)) > s.opts.SegmentSize {
		if err := s.sealLocked(ctx); err != nil {
			return Position{}, err
		}
		if err := s.ensureWriter(ctx); err != nil {
			return Position{}, err
		}
	}
	position := Position{SegmentID: s.writer.id, RecordOffset: s.writer.size, BatchSequence: sequence, BatchID: batch.GetHeader().GetBatchId()}
	if _, err := s.writer.file.Write(record); err != nil {
		return Position{}, fmt.Errorf("append segment: %w", err)
	}
	s.writer.size += int64(len(record))
	s.writer.records++
	s.writer.lastSequence = sequence
	if s.writer.firstSequence == 0 {
		s.writer.firstSequence = sequence
	}
	if err := s.upsertSegment(ctx, s.writer, "open", 0); err != nil {
		return Position{}, err
	}
	s.advanceSequenceCursor(batch)
	if err := s.persistSequenceCursor(ctx); err != nil {
		return Position{}, err
	}
	s.batchPositions[position.BatchID] = position
	return position, nil
}

func (s *Store) Seal(ctx context.Context) error {
	s.segmentMu.Lock()
	defer s.segmentMu.Unlock()
	return s.sealLocked(ctx)
}

func (s *Store) ensureWriter(ctx context.Context) error {
	if s.writer != nil {
		return nil
	}
	id, err := s.nextSegmentID(ctx)
	if err != nil {
		return err
	}
	path := filepath.Join(s.rootDir, "spool", fmt.Sprintf("%016d.open", id))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encodeSegmentHeader(id, time.Now().UTC())); err != nil {
		_ = file.Close()
		return err
	}
	s.writer = &segmentWriter{file: file, id: id, path: path, size: segmentHeaderSize}
	return s.upsertSegment(ctx, s.writer, "open", 0)
}

func (s *Store) sealLocked(ctx context.Context) error {
	if s.writer == nil {
		return nil
	}
	if err := s.writer.file.Sync(); err != nil {
		return err
	}
	if err := s.writer.file.Close(); err != nil {
		return err
	}
	sealed := s.writer.path[:len(s.writer.path)-len(".open")] + ".seg"
	if err := os.Rename(s.writer.path, sealed); err != nil {
		return err
	}
	s.writer.path = sealed
	if err := s.upsertSegment(ctx, s.writer, "sealed", time.Now().UTC().UnixNano()); err != nil {
		return err
	}
	s.writer = nil
	return nil
}

func (w *segmentWriter) close() error {
	if w == nil || w.file == nil {
		return nil
	}
	return w.file.Close()
}

func (s *Store) nextSegmentID(ctx context.Context) (uint64, error) {
	var id uint64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(segment_id), 0) + 1 FROM segments").Scan(&id)
	return id, err
}

func (s *Store) upsertSegment(ctx context.Context, writer *segmentWriter, state string, sealedAt int64) error {
	var sealed any
	if sealedAt > 0 {
		sealed = sealedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO segments(segment_id,path,state,first_sequence,last_sequence,record_count,bytes,created_at_ns,sealed_at_ns)
VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(segment_id) DO UPDATE SET path=excluded.path,state=excluded.state,first_sequence=excluded.first_sequence,
last_sequence=excluded.last_sequence,record_count=excluded.record_count,bytes=excluded.bytes,sealed_at_ns=excluded.sealed_at_ns`,
		writer.id, writer.path, state, writer.firstSequence, writer.lastSequence, writer.records, writer.size, time.Now().UTC().UnixNano(), sealed)
	return err
}
