package response

import (
	"encoding/json"
	"fmt"
	"time"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type commandDocument struct {
	ResponseID        string             `json:"response_id"`
	TenantID          string             `json:"tenant_id"`
	AgentID           string             `json:"agent_id"`
	PolicyID          string             `json:"policy_id,omitempty"`
	PolicyVersion     uint64             `json:"policy_version,omitempty"`
	SignalID          string             `json:"signal_id,omitempty"`
	Labels            map[string]string  `json:"labels,omitempty"`
	Scope             scopeDocument      `json:"scope,omitempty"`
	Action            string             `json:"action"`
	Mode              string             `json:"mode"`
	Target            string             `json:"target,omitempty"`
	Reason            string             `json:"reason,omitempty"`
	Status            string             `json:"status"`
	Actor             string             `json:"actor,omitempty"`
	ApprovalRequired  bool               `json:"approval_required,omitempty"`
	ApprovalStatus    string             `json:"approval_status,omitempty"`
	ApprovalThreshold uint32             `json:"approval_threshold,omitempty"`
	ApprovalRoles     []string           `json:"approval_roles,omitempty"`
	Approvals         []approvalDocument `json:"approvals,omitempty"`
	ApprovedBy        string             `json:"approved_by,omitempty"`
	ApprovedAt        time.Time          `json:"approved_at,omitempty"`
	CreatedAt         time.Time          `json:"created_at,omitempty"`
	UpdatedAt         time.Time          `json:"updated_at,omitempty"`
}

type scopeDocument struct {
	Type     string `json:"type,omitempty"`
	Selector string `json:"selector,omitempty"`
}

type approvalDocument struct {
	Actor      string    `json:"actor,omitempty"`
	Role       string    `json:"role,omitempty"`
	Approved   bool      `json:"approved"`
	Reason     string    `json:"reason,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
}

type acknowledgementDocument struct {
	ResponseID  string    `json:"response_id"`
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	Accepted    bool      `json:"accepted"`
	Unsupported bool      `json:"unsupported"`
	ObserveOnly bool      `json:"observe_only"`
	Executed    bool      `json:"executed"`
	Message     string    `json:"message,omitempty"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
}

func encodeCommand(value domainresponse.Command) ([]byte, error) {
	approvals := make([]approvalDocument, 0, len(value.Approvals))
	for _, item := range value.Approvals {
		approvals = append(approvals, approvalDocument{item.Actor, item.Role, item.Approved, item.Reason, item.ObservedAt})
	}
	return json.Marshal(commandDocument{
		ResponseID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, SignalID: value.SignalID, Labels: value.Labels,
		Scope: scopeDocument{value.Scope.Type, value.Scope.Selector}, Action: value.Action, Mode: value.Mode,
		Target: value.Target, Reason: value.Reason, Status: string(value.Status), Actor: value.Actor,
		ApprovalRequired: value.ApprovalRequired, ApprovalStatus: string(value.ApprovalStatus),
		ApprovalThreshold: value.ApprovalThreshold, ApprovalRoles: value.ApprovalRoles, Approvals: approvals,
		ApprovedBy: value.ApprovedBy, ApprovedAt: value.ApprovedAt, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	})
}

func decodeCommand(raw []byte, ackRaw []byte) (domainresponse.Command, error) {
	var document commandDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return domainresponse.Command{}, fmt.Errorf("decode response command: %w", err)
	}
	tenantID, err := tenant.NewID(document.TenantID)
	if err != nil {
		return domainresponse.Command{}, err
	}
	approvals := make([]domainresponse.Approval, 0, len(document.Approvals))
	for _, item := range document.Approvals {
		approvals = append(approvals, domainresponse.Approval{Actor: item.Actor, Role: item.Role,
			Approved: item.Approved, Reason: item.Reason, ObservedAt: item.ObservedAt})
	}
	value := domainresponse.Command{
		ID: document.ResponseID, TenantID: tenantID, AgentID: document.AgentID, PolicyID: document.PolicyID,
		PolicyVersion: document.PolicyVersion, SignalID: document.SignalID, Labels: document.Labels,
		Scope:  domainresponse.Scope{Type: document.Scope.Type, Selector: document.Scope.Selector},
		Action: document.Action, Mode: document.Mode, Target: document.Target, Reason: document.Reason,
		Status: domainresponse.Status(document.Status), Actor: document.Actor, ApprovalRequired: document.ApprovalRequired,
		ApprovalStatus: domainresponse.ApprovalState(document.ApprovalStatus), ApprovalThreshold: document.ApprovalThreshold,
		ApprovalRoles: document.ApprovalRoles, Approvals: approvals, ApprovedBy: document.ApprovedBy,
		ApprovedAt: document.ApprovedAt, CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
	}
	if len(ackRaw) > 0 {
		ack, err := decodeAcknowledgement(ackRaw)
		if err != nil {
			return domainresponse.Command{}, err
		}
		value.Ack = &ack
	}
	return value, nil
}

func encodeAcknowledgement(id string, value *domainresponse.Acknowledgement) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return json.Marshal(acknowledgementDocument{
		ResponseID: id, TenantID: value.TenantID.String(), AgentID: value.AgentID, Accepted: value.Accepted,
		Unsupported: value.Unsupported, ObserveOnly: value.ObserveOnly, Executed: value.Executed,
		Message: value.Message, ObservedAt: value.ObservedAt,
	})
}

func decodeAcknowledgement(raw []byte) (domainresponse.Acknowledgement, error) {
	var document acknowledgementDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return domainresponse.Acknowledgement{}, fmt.Errorf("decode response acknowledgement: %w", err)
	}
	tenantID, err := tenant.NewID(document.TenantID)
	if err != nil {
		return domainresponse.Acknowledgement{}, err
	}
	return domainresponse.Acknowledgement{TenantID: tenantID, AgentID: document.AgentID,
		Accepted: document.Accepted, Unsupported: document.Unsupported, ObserveOnly: document.ObserveOnly,
		Executed: document.Executed, Message: document.Message, ObservedAt: document.ObservedAt}, nil
}

func encodeAudit(value domainresponse.AuditRecord) ([]byte, error) {
	return json.Marshal(map[string]any{
		"audit_id": value.ID, "tenant_id": value.TenantID.String(), "response_id": value.ResponseID,
		"action": value.Action, "actor": value.Actor, "role": value.Role, "approved": value.Approved,
		"reason": value.Reason, "status": value.Status, "created_at": value.OccurredAt,
	})
}
