package policy

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UnitOfWork struct {
	db *sql.DB
}

func NewUnitOfWork(db *sql.DB) *UnitOfWork {
	return &UnitOfWork{db: db}
}

func (uow *UnitOfWork) Execute(ctx context.Context, fn func(context.Context, ports.PolicyTransaction) error) error {
	tx, err := uow.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy transaction: %w", err)
	}
	transaction := &transaction{executor: tx}
	if err := fn(ctx, transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("policy transaction failed: %v; rollback: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit policy transaction: %w", err)
	}
	return nil
}

type transaction struct {
	executor sqlExecutor
}

func (tx *transaction) Policies() ports.PolicyRepository { return repository{tx.executor} }
func (tx *transaction) Rules() ports.RuleRepository      { return ruleRepository{tx.executor} }
func (tx *transaction) Assignments() ports.AssignmentRepository {
	return assignmentRepository{tx.executor}
}
func (tx *transaction) Controls() ports.PolicyControlRepository {
	return controlRepository{tx.executor}
}
func (tx *transaction) Audits() ports.AuditRepository { return auditRepository{tx.executor} }

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
