package policy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
)

type policyEnvelope struct {
	TenantID  string    `json:"tenant_id"`
	PolicyID  string    `json:"policy_id"`
	Version   uint64    `json:"version"`
	Published bool      `json:"published"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Scope     struct {
		Type     string `json:"type,omitempty"`
		Selector string `json:"selector,omitempty"`
	} `json:"scope,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type policyColumns struct {
	scopeType     string
	scopeSelector string
	mode          string
}

func decodePolicy(tenantID tenant.ID, id domainpolicy.ID, version domainpolicy.Version, document []byte) (domainpolicy.Policy, error) {
	var envelope policyEnvelope
	if err := json.Unmarshal(document, &envelope); err != nil {
		return domainpolicy.Policy{}, fmt.Errorf("decode policy document: %w", err)
	}
	return domainpolicy.Policy{
		TenantID: tenantID, ID: id, Version: version, Published: envelope.Published,
		CreatedAt: envelope.CreatedAt, UpdatedAt: envelope.UpdatedAt, Document: append([]byte(nil), document...),
	}, nil
}

func encodePolicy(value domainpolicy.Policy) ([]byte, policyColumns, error) {
	document := value.Document
	if len(document) == 0 {
		document = []byte("{}")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return nil, policyColumns{}, fmt.Errorf("decode policy document: %w", err)
	}
	setJSONField(fields, "tenant_id", value.TenantID.String())
	setJSONField(fields, "policy_id", value.ID.String())
	setJSONField(fields, "version", uint64(value.Version))
	setJSONField(fields, "published", value.Published)
	setJSONField(fields, "created_at", value.CreatedAt)
	setJSONField(fields, "updated_at", value.UpdatedAt)
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, policyColumns{}, fmt.Errorf("encode policy document: %w", err)
	}
	var envelope policyEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, policyColumns{}, fmt.Errorf("read policy columns: %w", err)
	}
	return encoded, policyColumns{envelope.Scope.Type, envelope.Scope.Selector, envelope.Mode}, nil
}

func setJSONField(fields map[string]json.RawMessage, name string, value any) {
	encoded, _ := json.Marshal(value)
	fields[name] = encoded
}

func encodeAssignment(value domainpolicy.Assignment) ([]byte, error) {
	wire := struct {
		AssignmentID  string              `json:"assignment_id"`
		TenantID      string              `json:"tenant_id"`
		AgentID       string              `json:"agent_id,omitempty"`
		Scope         domainpolicy.Target `json:"-"`
		ScopeValue    scopeWire           `json:"scope,omitempty"`
		PolicyID      string              `json:"policy_id"`
		PolicyVersion uint64              `json:"policy_version"`
		CreatedAt     time.Time           `json:"created_at,omitempty"`
		UpdatedAt     time.Time           `json:"updated_at,omitempty"`
	}{
		AssignmentID: value.ID, TenantID: value.TenantID.String(), AgentID: value.Target.AgentID,
		ScopeValue: scopeWire{value.Target.ScopeType, value.Target.ScopeSelector}, PolicyID: value.PolicyID.String(),
		PolicyVersion: uint64(value.PolicyVersion), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
	return json.Marshal(wire)
}

type scopeWire struct {
	Type     string `json:"type,omitempty"`
	Selector string `json:"selector,omitempty"`
}

func encodeAudit(record audit.Record) ([]byte, error) {
	wire := struct {
		AuditID       string    `json:"audit_id"`
		TenantID      string    `json:"tenant_id"`
		Action        string    `json:"action"`
		PolicyID      string    `json:"policy_id,omitempty"`
		PolicyVersion uint64    `json:"policy_version,omitempty"`
		AssignmentID  string    `json:"assignment_id,omitempty"`
		Actor         string    `json:"actor,omitempty"`
		Status        string    `json:"status"`
		Reason        string    `json:"reason,omitempty"`
		CreatedAt     time.Time `json:"created_at,omitempty"`
	}{record.ID, record.TenantID.String(), record.Action, record.PolicyID, record.PolicyVersion,
		record.AssignmentID, record.Actor, record.Status, record.Reason, record.OccurredAt}
	return json.Marshal(wire)
}

func encodeControl(command ports.PolicyControlCommand) ([]byte, error) {
	wire := controlmodel.ControlCommand{
		CommandID: command.ID, TenantID: command.TenantID.String(), AgentID: command.AgentID,
		Type: controlmodel.ControlCommandTypePolicyUpdate, Status: controlmodel.ControlCommandStatusPending,
		PolicyID: command.PolicyID.String(), PolicyVersion: uint64(command.PolicyVersion),
		PayloadJSON: append([]byte(nil), command.Payload...), Actor: command.Actor, Reason: command.Reason,
		CreatedAt: command.CreatedAt, UpdatedAt: command.CreatedAt,
	}
	return json.Marshal(wire)
}
