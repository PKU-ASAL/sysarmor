package artifact

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UnitOfWork struct{ db *sql.DB }

func NewUnitOfWork(db *sql.DB) *UnitOfWork { return &UnitOfWork{db: db} }

func (uow *UnitOfWork) Execute(ctx context.Context, fn func(context.Context, ports.ArtifactTransaction) error) error {
	if uow == nil || uow.db == nil {
		return fmt.Errorf("artifact database is required")
	}
	tx, err := uow.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin artifact transaction: %w", err)
	}
	transaction := artifactTransaction{executor: tx}
	if err := fn(ctx, transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("artifact transaction failed: %v; rollback: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit artifact transaction: %w", err)
	}
	return nil
}

type artifactTransaction struct{ executor sqlExecutor }

func (tx artifactTransaction) Artifacts() ports.ArtifactRepository {
	return artifactRepository{executor: tx.executor}
}

func (tx artifactTransaction) Channels() ports.ArtifactChannelRepository {
	return channelRepository{executor: tx.executor}
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
