package backend

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/postgres"
)

const (
	KindFile     = "file"
	KindMemory   = "memory"
	KindPostgres = "postgres"
)

type Options struct {
	Kind           string
	Path           string
	PostgresDriver string
	PostgresDSN    string
	// BaseContext is the long-lived context bound to backend operations (e.g. a
	// server-lifetime context). It is intentionally separate from the context
	// passed to Open, which is only used for startup work such as migrations and
	// may carry a short startup timeout. When nil, context.Background() is used.
	BaseContext context.Context
}

type Result struct {
	Store     *store.Store
	DB        *sql.DB
	Migration postgres.MigrationResult
	close     func() error
}

func (r Result) Close() error {
	if r.close == nil {
		return nil
	}
	return r.close()
}

func Open(ctx context.Context, opts Options) (Result, error) {
	switch kind := normalizeKind(opts.Kind); kind {
	case KindFile:
		st, err := store.Open(opts.Path)
		if err != nil {
			return Result{}, err
		}
		return Result{Store: st}, nil
	case KindMemory:
		st, err := store.Open("")
		if err != nil {
			return Result{}, err
		}
		return Result{Store: st}, nil
	case KindPostgres:
		if opts.PostgresDriver == "" {
			return Result{}, fmt.Errorf("postgres driver is required")
		}
		if opts.PostgresDSN == "" {
			return Result{}, fmt.Errorf("postgres dsn is required")
		}
		db, err := sql.Open(opts.PostgresDriver, opts.PostgresDSN)
		if err != nil {
			return Result{}, fmt.Errorf("open postgres: %w", err)
		}
		migration, err := postgres.ApplyMigrations(ctx, db)
		if err != nil {
			_ = db.Close()
			return Result{}, err
		}
		baseCtx := opts.BaseContext
		if baseCtx == nil {
			baseCtx = context.Background()
		}
		st, err := postgres.OpenTableStore(baseCtx, db, migration)
		if err != nil {
			_ = db.Close()
			return Result{}, err
		}
		return Result{Store: st, DB: db, Migration: migration, close: db.Close}, nil
	default:
		return Result{}, fmt.Errorf("unknown store backend %q", opts.Kind)
	}
}

func normalizeKind(kind string) string {
	if kind == "" {
		return KindPostgres
	}
	return kind
}
