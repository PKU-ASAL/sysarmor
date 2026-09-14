package control

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UnitOfWork struct{ db *sql.DB }

func NewUnitOfWork(db *sql.DB) *UnitOfWork { return &UnitOfWork{db: db} }

func (uow *UnitOfWork) Execute(ctx context.Context, fn func(context.Context, ports.ControlTransaction) error) error {
	tx, err := uow.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin control transaction: %w", err)
	}
	transaction := &transaction{executor: tx}
	if err := fn(ctx, transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("control transaction failed: %v; rollback: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit control transaction: %w", err)
	}
	return nil
}

type transaction struct{ executor controlSQLExecutor }

func (tx *transaction) Commands() ports.ControlRepository    { return commandRepository{tx.executor} }
func (tx *transaction) Evidence() ports.EvidenceRepository   { return evidenceRepository{tx.executor} }
func (tx *transaction) Audits() ports.ControlAuditRepository { return auditRepository{tx.executor} }

type controlSQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
