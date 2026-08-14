package sqlite

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type ReadOptions struct {
	Limit        int
	FromSequence uint64
}
type StoredBatch struct {
	Position Position
	Batch    *dataplanev1.DataBatch
}

type tailMode uint8

const (
	tailStrict tailMode = iota
	tailIgnore
	tailTruncate
)

func (s *Store) ReadBatches(_ context.Context, opts ReadOptions) ([]StoredBatch, error) {
	files, err := segmentFiles(filepath.Join(s.rootDir, "spool"))
	if err != nil {
		return nil, err
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	var out []StoredBatch
	for _, path := range files {
		mode := tailStrict
		if strings.HasSuffix(path, ".open") {
			mode = tailIgnore
		}
		batches, err := readSegment(path, mode)
		if err != nil {
			return nil, err
		}
		for _, batch := range batches {
			if batch.Position.BatchSequence < opts.FromSequence {
				continue
			}
			out = append(out, batch)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

func (s *Store) recoverSegments(ctx context.Context) error {
	if err := s.loadSequenceCursor(ctx); err != nil {
		return err
	}
	files, err := segmentFiles(filepath.Join(s.rootDir, "spool"))
	if err != nil {
		return err
	}
	for _, path := range files {
		open := strings.HasSuffix(path, ".open")
		mode := tailStrict
		if open {
			mode = tailTruncate
		}
		batches, err := readSegment(path, mode)
		if err != nil {
			return err
		}
		if err := s.reconcileSegment(ctx, path, batches, open); err != nil {
			return err
		}
		for _, batch := range batches {
			s.advanceSequenceCursor(batch.Batch)
			s.batchPositions[batch.Position.BatchID] = batch.Position
		}
		if open {
			if s.writer != nil {
				return fmt.Errorf("multiple open segments")
			}
			writer, err := openRecoveredWriter(path, batches)
			if err != nil {
				return err
			}
			s.writer = writer
		}
	}
	return s.persistSequenceCursor(ctx)
}

func openRecoveredWriter(path string, batches []StoredBatch) (*segmentWriter, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	writer := &segmentWriter{file: file, path: path, size: info.Size(), records: uint64(len(batches))}
	if len(batches) > 0 {
		writer.id = batches[0].Position.SegmentID
		writer.firstSequence = batches[0].Position.BatchSequence
		writer.lastSequence = batches[len(batches)-1].Position.BatchSequence
		return writer, nil
	}
	header := make([]byte, segmentHeaderSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	writer.id, err = parseSegmentHeader(header)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return writer, nil
}

func readSegment(path string, mode tailMode) ([]StoredBatch, error) {
	flag := os.O_RDONLY
	if mode == tailTruncate {
		flag = os.O_RDWR
	}
	file, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	header := make([]byte, segmentHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil {
		return nil, err
	}
	segmentID, err := parseSegmentHeader(header)
	if err != nil {
		return nil, err
	}
	return readRecords(file, segmentID, mode)
}

func readRecords(file *os.File, segmentID uint64, mode tailMode) ([]StoredBatch, error) {
	var out []StoredBatch
	offset := int64(segmentHeaderSize)
	for {
		lengthRaw := make([]byte, 4)
		_, err := io.ReadFull(file, lengthRaw)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return handleIncompleteTail(file, offset, mode, out, err)
		}
		length := int(binary.BigEndian.Uint32(lengthRaw))
		if length < recordFixedSize || length > maxBatchBytes {
			return nil, fmt.Errorf("invalid record length %d", length)
		}
		record := append(lengthRaw, make([]byte, length)...)
		if _, err := io.ReadFull(file, record[4:]); err != nil {
			return handleIncompleteTail(file, offset, mode, out, err)
		}
		batch, sequence, err := decodeRecord(record)
		if err != nil {
			return nil, err
		}
		out = append(out, StoredBatch{Position: Position{SegmentID: segmentID, RecordOffset: offset, BatchSequence: sequence, BatchID: batch.GetHeader().GetBatchId()}, Batch: batch})
		offset += int64(len(record))
	}
}

func handleIncompleteTail(file *os.File, offset int64, mode tailMode, batches []StoredBatch, cause error) ([]StoredBatch, error) {
	if !errors.Is(cause, io.EOF) && !errors.Is(cause, io.ErrUnexpectedEOF) {
		return nil, cause
	}
	if mode == tailStrict {
		return nil, cause
	}
	if mode == tailTruncate {
		if err := file.Truncate(offset); err != nil {
			return nil, err
		}
	}
	return batches, nil
}

func segmentFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".seg") || strings.HasSuffix(entry.Name(), ".open")) {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func (s *Store) reconcileSegment(ctx context.Context, path string, batches []StoredBatch, open bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	writer := &segmentWriter{path: path, size: info.Size()}
	if len(batches) > 0 {
		writer.id = batches[0].Position.SegmentID
		writer.firstSequence = batches[0].Position.BatchSequence
		writer.lastSequence = batches[len(batches)-1].Position.BatchSequence
		writer.records = uint64(len(batches))
	} else {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		header := make([]byte, segmentHeaderSize)
		if _, err := io.ReadFull(file, header); err != nil {
			return err
		}
		writer.id, err = parseSegmentHeader(header)
		if err != nil {
			return err
		}
	}
	state := "sealed"
	if open {
		state = "open"
	}
	return s.upsertSegment(ctx, writer, state, 0)
}
