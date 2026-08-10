package enrollment

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type UnitOfWork struct{ db *sql.DB }

func NewUnitOfWork(db *sql.DB) *UnitOfWork { return &UnitOfWork{db: db} }

func (uow *UnitOfWork) Execute(ctx context.Context, fn func(context.Context, ports.EnrollmentTransaction) error) error {
	if uow == nil || uow.db == nil {
		return fmt.Errorf("enrollment database is required")
	}
	tx, err := uow.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrollment transaction: %w", err)
	}
	transaction := transaction{executor: tx}
	if err := fn(ctx, transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("enrollment transaction failed: %v; rollback: %w", err, rollbackErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrollment transaction: %w", err)
	}
	return nil
}

type transaction struct{ executor sqlExecutor }

func (tx transaction) Enrollments() ports.EnrollmentRepository {
	return enrollmentRepository{executor: tx.executor}
}

func (tx transaction) InstallMaterials() ports.InstallMaterialRepository {
	return installMaterialRepository{executor: tx.executor}
}

func (tx transaction) Certificates() ports.CertificateRepository {
	return certificateRepository{executor: tx.executor}
}

func (tx transaction) Unenrollments() ports.UnenrollmentRepository {
	return unenrollmentRepository{executor: tx.executor}
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
