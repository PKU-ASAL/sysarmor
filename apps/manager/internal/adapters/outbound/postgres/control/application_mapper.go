package control

import (
	"encoding/json"
	"fmt"
	"time"

	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type commandDocument struct {
	CommandID        string          `json:"command_id"`
	TenantID         string          `json:"tenant_id"`
	AgentID          string          `json:"agent_id"`
	Type             string          `json:"type"`
	Status           string          `json:"status"`
	PolicyID         string          `json:"policy_id,omitempty"`
	PolicyVersion    uint64          `json:"policy_version,omitempty"`
	ContentRef       string          `json:"content_ref,omitempty"`
	ContentKind      string          `json:"content_kind,omitempty"`
	ContentVersion   string          `json:"content_version,omitempty"`
	Payload          json.RawMessage `json:"payload_json,omitempty"`
	Actor            string          `json:"actor,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	CreatedAt        time.Time       `json:"created_at,omitempty"`
	UpdatedAt        time.Time       `json:"updated_at,omitempty"`
	SentAt           time.Time       `json:"sent_at,omitempty"`
	LastSentAt       time.Time       `json:"last_sent_at,omitempty"`
	AckedAt          time.Time       `json:"acked_at,omitempty"`
	CanceledAt       time.Time       `json:"canceled_at,omitempty"`
	ExpiredAt        time.Time       `json:"expired_at,omitempty"`
	AttemptCount     uint32          `json:"attempt_count,omitempty"`
	AckStatus        string          `json:"ack_status,omitempty"`
	AckMessage       string          `json:"ack_message,omitempty"`
	AckPolicyID      string          `json:"ack_policy_id,omitempty"`
	AckPolicyVersion uint64          `json:"ack_policy_version,omitempty"`
	AckReport        string          `json:"ack_report_json,omitempty"`
	Error            string          `json:"error,omitempty"`
}

func encodeCommand(value domaincontrol.Command) ([]byte, error) {
	document := commandDocument{CommandID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		Type: string(value.Type), Status: string(value.Status), PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion,
		ContentRef: value.ContentRef, ContentKind: value.ContentKind, ContentVersion: value.ContentVersion,
		Payload: append(json.RawMessage(nil), value.Payload...), Actor: value.Actor, Reason: value.Reason,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, SentAt: value.SentAt, LastSentAt: value.LastSentAt,
		AckedAt: value.AckedAt, CanceledAt: value.CanceledAt, ExpiredAt: value.ExpiredAt, AttemptCount: value.AttemptCount,
		AckStatus: string(value.AckStatus), AckMessage: value.AckMessage, AckPolicyID: value.AckPolicyID,
		AckPolicyVersion: value.AckPolicyVer, AckReport: value.AckReport, Error: value.Error}
	return json.Marshal(document)
}

func decodeCommand(raw []byte) (domaincontrol.Command, error) {
	var document commandDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return domaincontrol.Command{}, fmt.Errorf("decode control command: %w", err)
	}
	tenantID, err := tenant.NewID(document.TenantID)
	if err != nil {
		return domaincontrol.Command{}, err
	}
	return domaincontrol.Command{ID: document.CommandID, TenantID: tenantID, AgentID: document.AgentID,
		Type: domaincontrol.CommandType(document.Type), Status: domaincontrol.CommandStatus(document.Status),
		PolicyID: document.PolicyID, PolicyVersion: document.PolicyVersion, ContentRef: document.ContentRef,
		ContentKind: document.ContentKind, ContentVersion: document.ContentVersion, Payload: append([]byte(nil), document.Payload...),
		Actor: document.Actor, Reason: document.Reason, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		SentAt: document.SentAt, LastSentAt: document.LastSentAt, AckedAt: document.AckedAt,
		CanceledAt: document.CanceledAt, ExpiredAt: document.ExpiredAt, AttemptCount: document.AttemptCount,
		AckStatus: domaincontrol.CommandStatus(document.AckStatus), AckMessage: document.AckMessage,
		AckPolicyID: document.AckPolicyID, AckPolicyVer: document.AckPolicyVersion, AckReport: document.AckReport,
		Error: document.Error}, nil
}

type evidenceDocument struct {
	RequestID   string            `json:"request_id"`
	TenantID    string            `json:"tenant_id"`
	AgentID     string            `json:"agent_id"`
	IncidentID  string            `json:"incident_id,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Target      string            `json:"target,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Status      string            `json:"status"`
	ResultOK    bool              `json:"result_ok,omitempty"`
	Result      string            `json:"result,omitempty"`
	Evidence    json.RawMessage   `json:"evidence,omitempty"`
	Actor       string            `json:"actor,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	CompletedAt time.Time         `json:"completed_at,omitempty"`
}

func encodeEvidence(value domaincontrol.EvidencePullback) ([]byte, error) {
	return json.Marshal(evidenceDocument{RequestID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		IncidentID: value.IncidentID, Labels: value.Labels, Target: value.Target, Reason: value.Reason,
		Status: string(value.Status), ResultOK: value.ResultOK, Result: value.Result,
		Evidence: append(json.RawMessage(nil), value.Evidence...), Actor: value.Actor,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, CompletedAt: value.CompletedAt})
}

func decodeEvidence(raw []byte) (domaincontrol.EvidencePullback, error) {
	var document evidenceDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return domaincontrol.EvidencePullback{}, fmt.Errorf("decode evidence pullback: %w", err)
	}
	tenantID, err := tenant.NewID(document.TenantID)
	if err != nil {
		return domaincontrol.EvidencePullback{}, err
	}
	return domaincontrol.EvidencePullback{ID: document.RequestID, TenantID: tenantID, AgentID: document.AgentID,
		IncidentID: document.IncidentID, Labels: document.Labels, Target: document.Target, Reason: document.Reason,
		Status: domaincontrol.EvidenceStatus(document.Status), ResultOK: document.ResultOK, Result: document.Result,
		Evidence: append([]byte(nil), document.Evidence...), Actor: document.Actor,
		CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt, CompletedAt: document.CompletedAt}, nil
}

func encodeAudit(value domaincontrol.AuditRecord) ([]byte, error) {
	return json.Marshal(map[string]any{"audit_id": value.ID, "tenant_id": value.TenantID.String(),
		"resource_id": value.ResourceID, "action": value.Action, "actor": value.Actor,
		"reason": value.Reason, "status": value.Status, "created_at": value.OccurredAt})
}
