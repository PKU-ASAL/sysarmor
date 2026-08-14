package contracts

import (
	"encoding/json"
	"fmt"
	"time"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
)

type responseCommandWire struct {
	ResponseID        string                 `json:"response_id"`
	TenantID          string                 `json:"tenant_id"`
	AgentID           string                 `json:"agent_id"`
	PolicyID          string                 `json:"policy_id,omitempty"`
	PolicyVersion     uint64                 `json:"policy_version,omitempty"`
	SignalID          string                 `json:"signal_id,omitempty"`
	Labels            map[string]string      `json:"labels,omitempty"`
	Scope             responseScopeWire      `json:"scope,omitempty"`
	Action            string                 `json:"action"`
	Mode              string                 `json:"mode"`
	Target            string                 `json:"target,omitempty"`
	Reason            string                 `json:"reason,omitempty"`
	Status            string                 `json:"status"`
	Actor             string                 `json:"actor,omitempty"`
	ApprovalRequired  bool                   `json:"approval_required,omitempty"`
	ApprovalStatus    string                 `json:"approval_status,omitempty"`
	ApprovalThreshold uint32                 `json:"approval_threshold,omitempty"`
	ApprovalRoles     []string               `json:"approval_roles,omitempty"`
	Approvals         []responseApprovalWire `json:"approvals,omitempty"`
	ApprovedBy        string                 `json:"approved_by,omitempty"`
	ApprovedAt        time.Time              `json:"approved_at,omitempty"`
	CreatedAt         time.Time              `json:"created_at,omitempty"`
	UpdatedAt         time.Time              `json:"updated_at,omitempty"`
}

type responseScopeWire struct {
	Type     string `json:"type,omitempty"`
	Selector string `json:"selector,omitempty"`
}

type responseApprovalWire struct {
	Actor      string    `json:"actor,omitempty"`
	Role       string    `json:"role,omitempty"`
	Approved   bool      `json:"approved"`
	Reason     string    `json:"reason,omitempty"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
}

func DecodeResponseCommand(document []byte) (domainresponse.Command, error) {
	var wire responseCommandWire
	if err := json.Unmarshal(document, &wire); err != nil {
		return domainresponse.Command{}, fmt.Errorf("decode response command: %w", err)
	}
	return domainResponseCommand(wire), nil
}

func EncodeResponseCommand(command domainresponse.Command) ([]byte, error) {
	document, err := json.Marshal(wireResponseCommand(command))
	if err != nil {
		return nil, fmt.Errorf("encode response command: %w", err)
	}
	return document, nil
}

func domainResponseCommand(wire responseCommandWire) domainresponse.Command {
	command := domainresponse.Command{
		ID: wire.ResponseID, TenantID: wire.TenantID, AgentID: wire.AgentID,
		PolicyID: wire.PolicyID, PolicyVersion: wire.PolicyVersion, SignalID: wire.SignalID,
		Labels: cloneLabels(wire.Labels),
		Scope:  domainresponse.Scope{Type: wire.Scope.Type, Selector: wire.Scope.Selector},
		Action: wire.Action, Mode: domainresponse.Mode(wire.Mode), Target: wire.Target,
		Reason: wire.Reason, Status: wire.Status, Actor: wire.Actor,
		ApprovalRequired: wire.ApprovalRequired, ApprovalStatus: wire.ApprovalStatus,
		ApprovalThreshold: wire.ApprovalThreshold, ApprovalRoles: cloneStrings(wire.ApprovalRoles),
		ApprovedBy: wire.ApprovedBy, ApprovedAt: wire.ApprovedAt,
		CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
	}
	for _, approval := range wire.Approvals {
		command.Approvals = append(command.Approvals, domainresponse.Approval{
			Actor: approval.Actor, Role: approval.Role, Approved: approval.Approved,
			Reason: approval.Reason, ObservedAt: approval.ObservedAt,
		})
	}
	return command
}

func wireResponseCommand(command domainresponse.Command) responseCommandWire {
	wire := responseCommandWire{
		ResponseID: command.ID, TenantID: command.TenantID, AgentID: command.AgentID,
		PolicyID: command.PolicyID, PolicyVersion: command.PolicyVersion, SignalID: command.SignalID,
		Labels: cloneLabels(command.Labels),
		Scope:  responseScopeWire{Type: command.Scope.Type, Selector: command.Scope.Selector},
		Action: command.Action, Mode: string(command.Mode), Target: command.Target,
		Reason: command.Reason, Status: command.Status, Actor: command.Actor,
		ApprovalRequired: command.ApprovalRequired, ApprovalStatus: command.ApprovalStatus,
		ApprovalThreshold: command.ApprovalThreshold, ApprovalRoles: cloneStrings(command.ApprovalRoles),
		ApprovedBy: command.ApprovedBy, ApprovedAt: command.ApprovedAt,
		CreatedAt: command.CreatedAt, UpdatedAt: command.UpdatedAt,
	}
	for _, approval := range command.Approvals {
		wire.Approvals = append(wire.Approvals, responseApprovalWire{
			Actor: approval.Actor, Role: approval.Role, Approved: approval.Approved,
			Reason: approval.Reason, ObservedAt: approval.ObservedAt,
		})
	}
	return wire
}
