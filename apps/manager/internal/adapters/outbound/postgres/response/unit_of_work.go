package response

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UnitOfWork struct{ db *sql.DB }

func NewUnitOfWork(db *sql.DB) *UnitOfWork { return &UnitOfWork{db: db} }

func (uow *UnitOfWork) Execute(ctx context.Context, fn func(context.Context, ports.ResponseTransaction) error) error {
	if uow == nil || uow.db == nil {
		return fmt.Errorf("response database is required")
	}
	tx, err := uow.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin response transaction: %w", err)
	}
	transaction := &responseTransaction{executor: tx}
	if err := fn(ctx, transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("response transaction failed: %v; rollback: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit response transaction: %w", err)
	}
	return nil
}

type responseTransaction struct{ executor responseSQLExecutor }

func (tx *responseTransaction) Responses() ports.ResponseRepository { return repository{tx.executor} }
func (tx *responseTransaction) Audits() ports.ResponseAuditRepository {
	return auditRepository{tx.executor}
}

type responseSQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
