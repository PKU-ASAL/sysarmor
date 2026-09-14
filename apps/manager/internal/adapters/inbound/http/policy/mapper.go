package policy

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func policyDocument(value domainpolicy.Policy) any {
	fields := map[string]any{}
	if len(value.Document) > 0 {
		_ = json.Unmarshal(value.Document, &fields)
	}
	fields["tenant_id"] = value.TenantID.String()
	fields["policy_id"] = value.ID.String()
	fields["version"] = uint64(value.Version)
	fields["published"] = value.Published
	if !value.CreatedAt.IsZero() {
		fields["created_at"] = value.CreatedAt
	}
	if !value.UpdatedAt.IsZero() {
		fields["updated_at"] = value.UpdatedAt
	}
	return fields
}

func assignmentDocument(value domainpolicy.Assignment) any {
	return struct {
		AssignmentID  string    `json:"assignment_id"`
		TenantID      string    `json:"tenant_id"`
		AgentID       string    `json:"agent_id,omitempty"`
		Scope         scopeDTO  `json:"scope,omitempty"`
		PolicyID      string    `json:"policy_id"`
		PolicyVersion uint64    `json:"policy_version"`
		CreatedAt     time.Time `json:"created_at,omitempty"`
		UpdatedAt     time.Time `json:"updated_at,omitempty"`
	}{value.ID, value.TenantID.String(), value.Target.AgentID,
		scopeDTO{value.Target.ScopeType, value.Target.ScopeSelector}, value.PolicyID.String(),
		uint64(value.PolicyVersion), value.CreatedAt, value.UpdatedAt}
}

func assignmentDocuments(values []domainpolicy.Assignment) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, assignmentDocument(value))
	}
	return result
}

func auditDocuments(values []audit.Record) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"audit_id": value.ID, "tenant_id": value.TenantID.String(), "action": value.Action,
			"policy_id": value.PolicyID, "policy_version": value.PolicyVersion,
			"assignment_id": value.AssignmentID, "actor": value.Actor, "status": value.Status,
			"reason": value.Reason, "created_at": value.OccurredAt,
		})
	}
	return result
}

func controlDocument(value ports.PolicyControlCommand) any {
	return map[string]any{
		"command_id": value.ID, "tenant_id": value.TenantID.String(), "agent_id": value.AgentID,
		"type": "policy_update", "status": "pending", "policy_id": value.PolicyID.String(),
		"policy_version": uint64(value.PolicyVersion), "payload_json": json.RawMessage(value.Payload),
		"actor": value.Actor, "reason": value.Reason, "created_at": value.CreatedAt, "updated_at": value.CreatedAt,
	}
}

func parseUint(value string) uint64 {
	parsed, _ := strconv.ParseUint(value, 10, 64)
	return parsed
}
