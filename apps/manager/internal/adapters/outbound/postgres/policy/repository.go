package policy

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type repository struct{ db sqlExecutor }

func (repo repository) Get(ctx context.Context, tenantID tenant.ID, id domainpolicy.ID, version domainpolicy.Version) (domainpolicy.Policy, error) {
	if err := validatePolicyIdentity(tenantID, id); err != nil {
		return domainpolicy.Policy{}, err
	}
	if version == 0 {
		return repo.Current(ctx, tenantID, id)
	}
	return scanPolicy(repo.db.QueryRowContext(ctx, `
SELECT version, data FROM policies
WHERE tenant_id = $1 AND policy_id = $2 AND version = $3
`, tenantID.String(), id.String(), uint64(version)), tenantID, id)
}

func (repo repository) Current(ctx context.Context, tenantID tenant.ID, id domainpolicy.ID) (domainpolicy.Policy, error) {
	if err := validatePolicyIdentity(tenantID, id); err != nil {
		return domainpolicy.Policy{}, err
	}
	return scanPolicy(repo.db.QueryRowContext(ctx, `
SELECT version, data FROM policies
WHERE tenant_id = $1 AND policy_id = $2
ORDER BY version DESC LIMIT 1
`, tenantID.String(), id.String()), tenantID, id)
}

func (repo repository) Put(ctx context.Context, value domainpolicy.Policy) error {
	if err := validatePolicyIdentity(value.TenantID, value.ID); err != nil {
		return err
	}
	document, columns, err := encodePolicy(value)
	if err != nil {
		return err
	}
	_, err = repo.db.ExecContext(ctx, `
INSERT INTO policies (tenant_id, policy_id, version, scope_type, scope_selector, mode, created_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, policy_id, version) DO UPDATE SET
  scope_type = EXCLUDED.scope_type,
  scope_selector = EXCLUDED.scope_selector,
  mode = EXCLUDED.mode,
  data = EXCLUDED.data
`, value.TenantID.String(), value.ID.String(), uint64(value.Version), columns.scopeType, columns.scopeSelector, columns.mode, value.CreatedAt, document)
	if err != nil {
		return fmt.Errorf("put policy: %w", err)
	}
	return nil
}

type assignmentRepository struct{ db sqlExecutor }

func (repo assignmentRepository) Put(ctx context.Context, value domainpolicy.Assignment) error {
	if value.TenantID.IsZero() || value.ID == "" || value.PolicyID == "" || value.PolicyVersion == 0 {
		return failure.New(failure.InvalidArgument, "policy assignment identity is required")
	}
	document, err := encodeAssignment(value)
	if err != nil {
		return err
	}
	_, err = repo.db.ExecContext(ctx, `
INSERT INTO policy_assignments (tenant_id, assignment_id, agent_id, scope_type, scope_selector, policy_id, policy_version, created_at, updated_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, assignment_id) DO UPDATE SET
  agent_id = EXCLUDED.agent_id,
  scope_type = EXCLUDED.scope_type,
  scope_selector = EXCLUDED.scope_selector,
  policy_id = EXCLUDED.policy_id,
  policy_version = EXCLUDED.policy_version,
  updated_at = EXCLUDED.updated_at,
  data = EXCLUDED.data
`, value.TenantID.String(), value.ID, value.Target.AgentID, value.Target.ScopeType, value.Target.ScopeSelector,
		value.PolicyID.String(), uint64(value.PolicyVersion), value.CreatedAt, value.UpdatedAt, document)
	if err != nil {
		return fmt.Errorf("put policy assignment: %w", err)
	}
	return nil
}

type auditRepository struct{ db sqlExecutor }

func (repo auditRepository) Append(ctx context.Context, tenantID tenant.ID, record audit.Record) error {
	if tenantID.IsZero() || record.TenantID != tenantID || record.ID == "" {
		return failure.New(failure.InvalidArgument, "policy audit identity is required")
	}
	document, err := encodeAudit(record)
	if err != nil {
		return err
	}
	result, err := repo.db.ExecContext(ctx, `
INSERT INTO policy_audit (tenant_id, audit_id, action, policy_id, policy_version, assignment_id, actor, status, reason, created_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, audit_id) DO NOTHING
`, tenantID.String(), record.ID, record.Action, record.PolicyID, record.PolicyVersion, record.AssignmentID,
		record.Actor, record.Status, record.Reason, record.OccurredAt, document)
	if err != nil {
		return fmt.Errorf("append policy audit: %w", err)
	}
	return requireInserted(result, "policy audit already exists")
}

type controlRepository struct{ db sqlExecutor }

func (repo controlRepository) Put(ctx context.Context, command ports.PolicyControlCommand) error {
	if command.TenantID.IsZero() || command.ID == "" || command.AgentID == "" {
		return failure.New(failure.InvalidArgument, "policy control command identity is required")
	}
	document, err := encodeControl(command)
	if err != nil {
		return err
	}
	result, err := repo.db.ExecContext(ctx, `
INSERT INTO control_commands (tenant_id, command_id, agent_id, command_type, status, policy_id, policy_version, actor, reason, created_at, updated_at, data)
VALUES ($1, $2, $3, 'policy_update', 'pending', $4, $5, $6, $7, $8, $8, $9)
ON CONFLICT (tenant_id, command_id) DO NOTHING
`, command.TenantID.String(), command.ID, command.AgentID, command.PolicyID.String(), uint64(command.PolicyVersion),
		command.Actor, command.Reason, command.CreatedAt, document)
	if err != nil {
		return fmt.Errorf("put policy control command: %w", err)
	}
	return requireInserted(result, "policy control command already exists")
}

func requireInserted(result sql.Result, message string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read insert result: %w", err)
	}
	if rows == 0 {
		return failure.New(failure.Conflict, message)
	}
	return nil
}

func validatePolicyIdentity(tenantID tenant.ID, id domainpolicy.ID) error {
	if tenantID.IsZero() || id == "" {
		return failure.New(failure.InvalidArgument, "tenant and policy ID are required")
	}
	return nil
}

func scanPolicy(row *sql.Row, tenantID tenant.ID, id domainpolicy.ID) (domainpolicy.Policy, error) {
	var version uint64
	var document []byte
	if err := row.Scan(&version, &document); err != nil {
		if err == sql.ErrNoRows {
			return domainpolicy.Policy{}, failure.New(failure.NotFound, "policy not found")
		}
		return domainpolicy.Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return decodePolicy(tenantID, id, domainpolicy.Version(version), document)
}
