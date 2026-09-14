package policy

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type repository struct{ db sqlExecutor }

type ruleRepository struct{ db sqlExecutor }

func (repo ruleRepository) List(ctx context.Context, tenantID tenant.ID, filter domainpolicy.RuleFilter) ([]domainpolicy.Rule, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT rule_where, data FROM rules
WHERE tenant_id = $1 AND ($2 = '' OR rule_where = $2)
ORDER BY rule_id ASC, version ASC
`, tenantID.String(), filter.Where)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()
	result := []domainpolicy.Rule{}
	for rows.Next() {
		var where string
		var document []byte
		if err := rows.Scan(&where, &document); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		if !json.Valid(document) {
			return nil, fmt.Errorf("decode rule: invalid JSON document")
		}
		result = append(result, domainpolicy.Rule{TenantID: tenantID, Where: where, Document: append([]byte(nil), document...)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rules: %w", err)
	}
	return result, nil
}

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

func (repo repository) Published(ctx context.Context, tenantID tenant.ID, id domainpolicy.ID, version domainpolicy.Version) (domainpolicy.Policy, error) {
	if err := validatePolicyIdentity(tenantID, id); err != nil {
		return domainpolicy.Policy{}, err
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT version, data FROM policies
WHERE tenant_id = $1 AND policy_id = $2 AND ($3 = 0 OR version = $3)
ORDER BY version DESC
`, tenantID.String(), id.String(), uint64(version))
	if err != nil {
		return domainpolicy.Policy{}, fmt.Errorf("query published policy: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rowVersion uint64
		var document []byte
		if err := rows.Scan(&rowVersion, &document); err != nil {
			return domainpolicy.Policy{}, fmt.Errorf("scan published policy: %w", err)
		}
		value, err := decodePolicy(tenantID, id, domainpolicy.Version(rowVersion), document)
		if err != nil {
			return domainpolicy.Policy{}, err
		}
		if value.Published {
			return value, nil
		}
	}
	if err := rows.Err(); err != nil {
		return domainpolicy.Policy{}, fmt.Errorf("iterate published policies: %w", err)
	}
	return domainpolicy.Policy{}, failure.New(failure.NotFound, "published policy not found")
}

func (repo repository) List(ctx context.Context, tenantID tenant.ID, filter domainpolicy.Filter) ([]domainpolicy.Policy, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT policy_id, version, data FROM policies
WHERE tenant_id = $1 AND ($2 = '' OR policy_id = $2)
ORDER BY policy_id ASC, version ASC
`, tenantID.String(), filter.PolicyID.String())
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()
	var result []domainpolicy.Policy
	for rows.Next() {
		var id string
		var version uint64
		var document []byte
		if err := rows.Scan(&id, &version, &document); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		value, err := decodePolicy(tenantID, domainpolicy.ID(id), domainpolicy.Version(version), document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies: %w", err)
	}
	return result, nil
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
INSERT INTO policies (tenant_id, policy_id, version, scope_type, scope_selector, protection_mode, created_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, policy_id, version) DO UPDATE SET
  scope_type = EXCLUDED.scope_type,
  scope_selector = EXCLUDED.scope_selector,
  protection_mode = EXCLUDED.protection_mode,
  data = EXCLUDED.data
`, value.TenantID.String(), value.ID.String(), uint64(value.Version), columns.scopeType, columns.scopeSelector, columns.protectionMode, value.CreatedAt, document)
	if err != nil {
		return fmt.Errorf("put policy: %w", err)
	}
	if value.Published {
		_, err = repo.db.ExecContext(ctx, `
INSERT INTO policy_snapshot_outbox (tenant_id, policy_id, policy_version, policy_document)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, policy_id, policy_version) DO UPDATE SET
  policy_document = EXCLUDED.policy_document,
  published_at = NULL,
  last_error = ''
`, value.TenantID.String(), value.ID.String(), uint64(value.Version), document)
		if err != nil {
			return fmt.Errorf("enqueue policy snapshot: %w", err)
		}
	}
	return nil
}

type assignmentRepository struct{ db sqlExecutor }

func (repo assignmentRepository) Candidates(ctx context.Context, tenantID tenant.ID, target domainpolicy.Target) ([]domainpolicy.Assignment, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT data FROM policy_assignments
WHERE tenant_id = $1 AND (
  ($2 <> '' AND agent_id = $2) OR
  (agent_id = '' AND scope_type = $3 AND (scope_selector = $4 OR scope_selector = ''))
)
ORDER BY CASE
  WHEN $2 <> '' AND agent_id = $2 THEN 30
	  WHEN scope_selector <> '' THEN 20
	  ELSE 10
	END DESC, updated_at DESC, assignment_id ASC
	`, tenantID.String(), target.AgentID, target.ScopeType, target.ScopeSelector)
	if err != nil {
		return nil, fmt.Errorf("query effective policy candidates: %w", err)
	}
	defer rows.Close()
	var result []domainpolicy.Assignment
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan effective policy candidate: %w", err)
		}
		value, err := decodeAssignment(tenantID, document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate effective policy candidates: %w", err)
	}
	return result, nil
}

func (repo assignmentRepository) List(ctx context.Context, tenantID tenant.ID, filter domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT data FROM policy_assignments
WHERE tenant_id = $1 AND ($2 = '' OR agent_id = $2)
ORDER BY assignment_id ASC
`, tenantID.String(), filter.AgentID)
	if err != nil {
		return nil, fmt.Errorf("list policy assignments: %w", err)
	}
	defer rows.Close()
	var result []domainpolicy.Assignment
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan policy assignment: %w", err)
		}
		value, err := decodeAssignment(tenantID, document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy assignments: %w", err)
	}
	return result, nil
}

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

func (repo auditRepository) List(ctx context.Context, tenantID tenant.ID, policyID domainpolicy.ID) ([]audit.Record, error) {
	if tenantID.IsZero() {
		return nil, failure.New(failure.InvalidArgument, "tenant is required")
	}
	rows, err := repo.db.QueryContext(ctx, `
SELECT data FROM policy_audit
WHERE tenant_id = $1 AND ($2 = '' OR policy_id = $2)
ORDER BY created_at ASC, audit_id ASC
`, tenantID.String(), policyID.String())
	if err != nil {
		return nil, fmt.Errorf("list policy audits: %w", err)
	}
	defer rows.Close()
	var result []audit.Record
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan policy audit: %w", err)
		}
		value, err := decodeAudit(tenantID, document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy audits: %w", err)
	}
	return result, nil
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
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read policy control insert result: %w", err)
	}
	if rows > 0 {
		return nil
	}
	return repo.requireSameCommand(ctx, command, document)
}

func (repo controlRepository) requireSameCommand(ctx context.Context, command ports.PolicyControlCommand, document []byte) error {
	var existing []byte
	err := repo.db.QueryRowContext(ctx, `
SELECT data FROM control_commands WHERE tenant_id = $1 AND command_id = $2
`, command.TenantID.String(), command.ID).Scan(&existing)
	if err != nil {
		return fmt.Errorf("read existing policy control command: %w", err)
	}
	if !bytes.Equal(existing, document) {
		return failure.New(failure.Conflict, "policy control command ID belongs to a different request")
	}
	return nil
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
