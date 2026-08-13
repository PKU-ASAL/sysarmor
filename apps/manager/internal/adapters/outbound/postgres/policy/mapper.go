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
	canonical, err := canonicalPolicyDocument(document, tenantID, id, version)
	if err != nil {
		return domainpolicy.Policy{}, err
	}
	downlink, err := EndpointDocument(canonical, id, version)
	if err != nil {
		return domainpolicy.Policy{}, err
	}
	return domainpolicy.Policy{
		TenantID: tenantID, ID: id, Version: version, Published: envelope.Published,
		CreatedAt: envelope.CreatedAt, UpdatedAt: envelope.UpdatedAt,
		Document: canonical, DownlinkDocument: downlink,
	}, nil
}

func canonicalPolicyDocument(document []byte, tenantID tenant.ID, id domainpolicy.ID, version domainpolicy.Version) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(document, &fields); err != nil {
		return nil, fmt.Errorf("decode policy document: %w", err)
	}
	setJSONField(fields, "tenant_id", tenantID.String())
	setJSONField(fields, "policy_id", id.String())
	setJSONField(fields, "version", uint64(version))
	canonical, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encode canonical policy identity: %w", err)
	}
	return canonical, nil
}

func EndpointDocument(document []byte, id domainpolicy.ID, version domainpolicy.Version) ([]byte, error) {
	var source map[string]json.RawMessage
	if err := json.Unmarshal(document, &source); err != nil {
		return nil, fmt.Errorf("decode endpoint policy source: %w", err)
	}
	endpoint := map[string]json.RawMessage{}
	setJSONField(endpoint, "policy_id", id.String())
	setJSONField(endpoint, "version", uint64(version))
	endpoint["collection"] = rawOrDefault(source["collection"], `{"behaviors":["process.exec","process.exit","process.fork","file.read","file.write","file.chmod","network.connect"],"observe_only":true}`)
	endpoint["detection"] = rawOrDefault(source["detection"], `{"policy_id":"default-endpoint-detection","version":1,"mode":"observe"}`)
	endpoint["telemetry"] = rawOrDefault(source["telemetry"], `{"max_batch_items":256,"max_batch_bytes":262144,"flush_interval":"1s"}`)
	endpoint["response"] = rawOrDefault(source["response_policy"], `{"allowed_actions":["collect","noop"],"allowed_modes":["observe"]}`)
	encoded, err := json.Marshal(endpoint)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint policy: %w", err)
	}
	return encoded, nil
}

func rawOrDefault(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) > 0 && string(value) != "null" {
		return append(json.RawMessage(nil), value...)
	}
	return json.RawMessage(fallback)
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

func decodeAssignment(tenantID tenant.ID, document []byte) (domainpolicy.Assignment, error) {
	var wire struct {
		AssignmentID  string    `json:"assignment_id"`
		AgentID       string    `json:"agent_id"`
		Scope         scopeWire `json:"scope"`
		PolicyID      string    `json:"policy_id"`
		PolicyVersion uint64    `json:"policy_version"`
		CreatedAt     time.Time `json:"created_at"`
		UpdatedAt     time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(document, &wire); err != nil {
		return domainpolicy.Assignment{}, fmt.Errorf("decode policy assignment: %w", err)
	}
	return domainpolicy.Assignment{
		ID: wire.AssignmentID, TenantID: tenantID,
		Target:   domainpolicy.Target{AgentID: wire.AgentID, ScopeType: wire.Scope.Type, ScopeSelector: wire.Scope.Selector},
		PolicyID: domainpolicy.ID(wire.PolicyID), PolicyVersion: domainpolicy.Version(wire.PolicyVersion),
		CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}, nil
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

func decodeAudit(tenantID tenant.ID, document []byte) (audit.Record, error) {
	var wire struct {
		AuditID       string    `json:"audit_id"`
		Action        string    `json:"action"`
		PolicyID      string    `json:"policy_id"`
		PolicyVersion uint64    `json:"policy_version"`
		AssignmentID  string    `json:"assignment_id"`
		Actor         string    `json:"actor"`
		Status        string    `json:"status"`
		Reason        string    `json:"reason"`
		CreatedAt     time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(document, &wire); err != nil {
		return audit.Record{}, fmt.Errorf("decode policy audit: %w", err)
	}
	return audit.Record{
		ID: wire.AuditID, TenantID: tenantID, Action: wire.Action, PolicyID: wire.PolicyID,
		PolicyVersion: wire.PolicyVersion, AssignmentID: wire.AssignmentID, Actor: wire.Actor,
		Status: wire.Status, Reason: wire.Reason, OccurredAt: wire.CreatedAt,
	}, nil
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
