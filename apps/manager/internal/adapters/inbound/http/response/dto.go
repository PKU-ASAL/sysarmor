package response

import (
	"time"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type commandRequest struct {
	ResponseID        string            `json:"response_id"`
	TenantID          string            `json:"tenant_id"`
	AgentID           string            `json:"agent_id"`
	PolicyID          string            `json:"policy_id,omitempty"`
	PolicyVersion     uint64            `json:"policy_version,omitempty"`
	SignalID          string            `json:"signal_id,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Scope             scopeDocument     `json:"scope,omitempty"`
	Action            string            `json:"action"`
	Mode              string            `json:"mode"`
	Target            string            `json:"target,omitempty"`
	Reason            string            `json:"reason,omitempty"`
	ApprovalRequired  bool              `json:"approval_required,omitempty"`
	ApprovalThreshold uint32            `json:"approval_threshold,omitempty"`
	ApprovalRoles     []string          `json:"approval_roles,omitempty"`
}

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

type auditDocument struct {
	Command commandDocument          `json:"command"`
	Ack     *acknowledgementDocument `json:"ack,omitempty"`
}

type approvalRequest struct {
	ResponseID string `json:"response_id"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	Approved   bool   `json:"approved"`
	Reason     string `json:"reason,omitempty"`
}

type decisionRequest struct {
	SignalID string        `json:"signal_id"`
	TenantID string        `json:"tenant_id"`
	AgentID  string        `json:"agent_id"`
	Scope    scopeDocument `json:"scope,omitempty"`
	Target   string        `json:"target,omitempty"`
}

func mapRequest(value commandRequest) domainresponse.Command {
	return domainresponse.Command{
		ID: value.ResponseID, TenantID: tenant.ID(value.TenantID), AgentID: value.AgentID,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, SignalID: value.SignalID, Labels: value.Labels,
		Scope: domainresponse.Scope{Type: value.Scope.Type, Selector: value.Scope.Selector}, Action: value.Action,
		Mode: value.Mode, Target: value.Target, Reason: value.Reason, ApprovalRequired: value.ApprovalRequired,
		ApprovalThreshold: value.ApprovalThreshold, ApprovalRoles: value.ApprovalRoles,
	}
}

func mapCommand(value domainresponse.Command) commandDocument {
	approvals := make([]approvalDocument, 0, len(value.Approvals))
	for _, item := range value.Approvals {
		approvals = append(approvals, approvalDocument{item.Actor, item.Role, item.Approved, item.Reason, item.ObservedAt})
	}
	return commandDocument{
		ResponseID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, SignalID: value.SignalID, Labels: value.Labels,
		Scope: scopeDocument{value.Scope.Type, value.Scope.Selector}, Action: value.Action, Mode: value.Mode,
		Target: value.Target, Reason: value.Reason, Status: string(value.Status), Actor: value.Actor,
		ApprovalRequired: value.ApprovalRequired, ApprovalStatus: string(value.ApprovalStatus),
		ApprovalThreshold: value.ApprovalThreshold, ApprovalRoles: value.ApprovalRoles, Approvals: approvals,
		ApprovedBy: value.ApprovedBy, ApprovedAt: value.ApprovedAt, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func mapAudit(value domainresponse.Command) auditDocument {
	document := auditDocument{Command: mapCommand(value)}
	if value.Ack != nil {
		document.Ack = &acknowledgementDocument{
			ResponseID: value.ID, TenantID: value.TenantID.String(), AgentID: value.Ack.AgentID,
			Accepted: value.Ack.Accepted, Unsupported: value.Ack.Unsupported, ObserveOnly: value.Ack.ObserveOnly,
			Executed: value.Ack.Executed, Message: value.Ack.Message, ObservedAt: value.Ack.ObservedAt,
		}
	}
	return document
}
