package response

import (
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type Status string
type ApprovalState string

const (
	StatusPendingApproval Status = "pending_approval"
	StatusPending         Status = "pending"
	StatusDenied          Status = "denied"
	StatusAcknowledged    Status = "acked"
)

const (
	ApprovalRequired ApprovalState = "required"
	ApprovalPartial  ApprovalState = "partial"
	ApprovalApproved ApprovalState = "approved"
	ApprovalRejected ApprovalState = "rejected"
)

type Scope struct{ Type, Selector string }

type Command struct {
	ID                string
	TenantID          tenant.ID
	AgentID           string
	PolicyID          string
	PolicyVersion     uint64
	SignalID          string
	Labels            map[string]string
	Scope             Scope
	Action            string
	Mode              string
	Target            string
	Reason            string
	Status            Status
	Actor             string
	ApprovalRequired  bool
	ApprovalStatus    ApprovalState
	ApprovalThreshold uint32
	ApprovalRoles     []string
	Approvals         []Approval
	ApprovedBy        string
	ApprovedAt        time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Ack               *Acknowledgement
}

type Approval struct {
	Actor      string
	Role       string
	Approved   bool
	Reason     string
	ObservedAt time.Time
}

type Acknowledgement struct {
	TenantID    tenant.ID
	AgentID     string
	Accepted    bool
	Unsupported bool
	ObserveOnly bool
	Executed    bool
	Message     string
	ObservedAt  time.Time
}

type Acknowledged struct {
	Command Command
	Ack     Acknowledgement
}

type AuditRecord struct {
	ID         string
	TenantID   tenant.ID
	ResponseID string
	Action     string
	Actor      string
	Role       string
	Approved   bool
	Reason     string
	Status     Status
	OccurredAt time.Time
}

func NewCommand(value Command, now time.Time) (Command, error) {
	if strings.TrimSpace(value.ID) == "" || value.TenantID.IsZero() || strings.TrimSpace(value.AgentID) == "" {
		return Command{}, failure.New(failure.InvalidArgument, "response command identity is required")
	}
	value.ID = strings.TrimSpace(value.ID)
	value.AgentID = strings.TrimSpace(value.AgentID)
	value.Action = defaultString(value.Action, "collect")
	value.Mode = defaultString(value.Mode, "observe")
	value.Labels = cloneLabels(value.Labels)
	value.ApprovalRoles = append([]string(nil), value.ApprovalRoles...)
	value.Approvals = append([]Approval(nil), value.Approvals...)
	value.Status = StatusPending
	if value.ApprovalRequired {
		value.Status, value.ApprovalStatus = StatusPendingApproval, ApprovalRequired
	}
	value.CreatedAt, value.UpdatedAt = now.UTC(), now.UTC()
	return value, nil
}

func (command Command) Decide(value Approval, now time.Time) (Command, error) {
	if !command.ApprovalRequired {
		return Command{}, failure.New(failure.FailedPrecondition, "response command is not awaiting approval")
	}
	if strings.TrimSpace(value.Actor) == "" || !roleAllowed(command.ApprovalRoles, value.Role) {
		return Command{}, failure.New(failure.PermissionDenied, "response approval role is not allowed")
	}
	for _, existing := range command.Approvals {
		if existing.Actor == value.Actor {
			if existing.Approved == value.Approved && existing.Role == value.Role && existing.Reason == value.Reason {
				return command, nil
			}
			return Command{}, failure.New(failure.Conflict, "response actor already decided")
		}
	}
	if command.Status != StatusPendingApproval {
		return Command{}, failure.New(failure.FailedPrecondition, "response command is not awaiting approval")
	}
	value.ObservedAt = now.UTC()
	command.Approvals = append(append([]Approval(nil), command.Approvals...), value)
	command.applyDecision(value, now.UTC())
	return command, nil
}

func (command *Command) applyDecision(value Approval, now time.Time) {
	command.UpdatedAt = now
	command.appendApprovalReason(value.Reason)
	if !value.Approved {
		command.Status, command.ApprovalStatus = StatusDenied, ApprovalRejected
		command.ApprovedBy, command.ApprovedAt = value.Actor, now
		return
	}
	if approvalCount(*command) < approvalThreshold(*command) {
		command.ApprovalStatus = ApprovalPartial
		return
	}
	command.Status, command.ApprovalStatus = StatusPending, ApprovalApproved
	command.ApprovedBy, command.ApprovedAt = value.Actor, now
}

func (command Command) Acknowledge(value Acknowledgement, now time.Time) (Acknowledged, error) {
	if command.TenantID != value.TenantID || command.AgentID != value.AgentID {
		return Acknowledged{}, failure.New(failure.Conflict, "response acknowledgement identity mismatch")
	}
	if command.Status == StatusAcknowledged {
		if command.Ack != nil && sameAcknowledgement(*command.Ack, value) {
			return Acknowledged{Command: command, Ack: *command.Ack}, nil
		}
		return Acknowledged{}, failure.New(failure.Conflict, "response command already acknowledged")
	}
	value.ObservedAt = now.UTC()
	command.Status, command.UpdatedAt = StatusAcknowledged, value.ObservedAt
	command.Ack = &value
	return Acknowledged{Command: command, Ack: value}, nil
}

func sameAcknowledgement(left, right Acknowledgement) bool {
	return left.TenantID == right.TenantID && left.AgentID == right.AgentID &&
		left.Accepted == right.Accepted && left.Unsupported == right.Unsupported &&
		left.ObserveOnly == right.ObserveOnly && left.Executed == right.Executed && left.Message == right.Message
}

func (command Command) appendApprovalReason(reason string) {
	if strings.TrimSpace(reason) == "" {
		return
	}
	if command.Reason == "" {
		command.Reason = reason
		return
	}
	command.Reason += "; approval: " + reason
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func roleAllowed(roles []string, role string) bool {
	role = strings.TrimSpace(role)
	if len(roles) == 0 || role == "admin" {
		return true
	}
	for _, allowed := range roles {
		if strings.TrimSpace(allowed) == role {
			return true
		}
	}
	return false
}

func approvalThreshold(command Command) uint32 {
	if command.ApprovalThreshold == 0 {
		return 1
	}
	return command.ApprovalThreshold
}

func approvalCount(command Command) uint32 {
	seen := map[string]bool{}
	for _, approval := range command.Approvals {
		if approval.Approved && roleAllowed(command.ApprovalRoles, approval.Role) {
			seen[approval.Actor] = true
		}
	}
	return uint32(len(seen))
}
