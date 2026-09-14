package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

const (
	defaultMaxBytes       = int64(10 << 30)
	defaultMinFreeBytes   = int64(2 << 30)
	defaultSegmentSize    = int64(64 << 20)
	defaultSignalMaxCount = int64(100_000)
)

type Options struct {
	RootDir        string
	MaxBytes       int64
	MinFreeBytes   int64
	SegmentSize    int64
	SignalMaxCount int64
}

type Store struct {
	db             *sql.DB
	rootDir        string
	opts           Options
	segmentMu      sync.Mutex
	writer         *segmentWriter
	batchPositions map[string]Position
	cursor         SequenceCursor
}

func Open(ctx context.Context, opts Options) (*Store, error) {
	opts = normalizeOptions(opts)
	if err := ensureDirectories(opts.RootDir); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(opts.RootDir, "agent.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open local state: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, rootDir: opts.RootDir, opts: opts, batchPositions: make(map[string]Position)}
	if err := store.initialize(ctx, dbPath); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.recoverSegments(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.segmentMu.Lock()
	if s.writer != nil {
		_ = s.writer.close()
	}
	s.segmentMu.Unlock()
	return s.db.Close()
}

func normalizeOptions(opts Options) Options {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	if opts.MinFreeBytes <= 0 {
		opts.MinFreeBytes = defaultMinFreeBytes
	}
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = defaultSegmentSize
	}
	if opts.SignalMaxCount <= 0 {
		opts.SignalMaxCount = defaultSignalMaxCount
	}
	return opts
}

func ensureDirectories(root string) error {
	if root == "" {
		return fmt.Errorf("local store root directory is required")
	}
	for _, path := range []string{root, filepath.Join(root, "spool")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create local store directory: %w", err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("secure local store directory: %w", err)
		}
	}
	return nil
}
