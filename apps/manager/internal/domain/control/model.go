package control

import (
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type CommandStatus string

type CommandType string

const (
	CommandPending  CommandStatus = "pending"
	CommandSent     CommandStatus = "sent"
	CommandApplied  CommandStatus = "applied"
	CommandRejected CommandStatus = "rejected"
	CommandFailed   CommandStatus = "failed"
	CommandCanceled CommandStatus = "canceled"
	CommandExpired  CommandStatus = "expired"
)

const (
	CommandTypePolicyUpdate  CommandType = "policy_update"
	CommandTypeContentUpdate CommandType = "content_update"
)

type Command struct {
	ID             string
	TenantID       tenant.ID
	AgentID        string
	Type           CommandType
	Status         CommandStatus
	PolicyID       string
	PolicyVersion  uint64
	ContentRef     string
	ContentKind    string
	ContentVersion string
	Payload        []byte
	Actor          string
	Reason         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	SentAt         time.Time
	LastSentAt     time.Time
	AckedAt        time.Time
	CanceledAt     time.Time
	ExpiredAt      time.Time
	AttemptCount   uint32
	AckStatus      CommandStatus
	AckMessage     string
	AckPolicyID    string
	AckPolicyVer   uint64
	AckReport      string
	Error          string
}

type Acknowledgement struct {
	Status        CommandStatus
	Message       string
	PolicyID      string
	PolicyVersion uint64
	Report        string
}

func NewCommand(value Command, now time.Time) (Command, error) {
	if strings.TrimSpace(value.ID) == "" || value.TenantID.IsZero() || strings.TrimSpace(value.AgentID) == "" {
		return Command{}, failure.New(failure.InvalidArgument, "control command identity is required")
	}
	if value.Type != CommandTypePolicyUpdate && value.Type != CommandTypeContentUpdate {
		return Command{}, failure.New(failure.InvalidArgument, "control command type is unsupported")
	}
	if len(value.Payload) == 0 {
		return Command{}, failure.New(failure.InvalidArgument, "control command payload is required")
	}
	value.ID = strings.TrimSpace(value.ID)
	value.AgentID = strings.TrimSpace(value.AgentID)
	value.Payload = append([]byte(nil), value.Payload...)
	value.Status = CommandPending
	value.CreatedAt = now.UTC()
	value.UpdatedAt = now.UTC()
	return value, nil
}

func (command Command) Acknowledge(ack Acknowledgement, observedAt time.Time) (Command, error) {
	if command.terminal() {
		if command.AckStatus == ack.Status && command.AckMessage == ack.Message &&
			command.AckPolicyID == ack.PolicyID && command.AckPolicyVer == ack.PolicyVersion &&
			command.AckReport == ack.Report {
			return command, nil
		}
		return Command{}, failure.New(failure.Conflict, "control command already completed")
	}
	command.Status = acknowledgementStatus(ack.Status)
	command.AckStatus = ack.Status
	command.AckMessage = ack.Message
	command.AckPolicyID = ack.PolicyID
	command.AckPolicyVer = ack.PolicyVersion
	command.AckReport = ack.Report
	if command.Status == CommandRejected || command.Status == CommandFailed {
		command.Error = ack.Message
	}
	command.AckedAt = observedAt
	command.UpdatedAt = observedAt
	return command, nil
}

func (command Command) MarkSent(sentAt time.Time) Command {
	if !command.terminal() {
		command.Status = CommandSent
	}
	if command.SentAt.IsZero() {
		command.SentAt = sentAt
	}
	command.LastSentAt = sentAt
	command.UpdatedAt = sentAt
	command.AttemptCount++
	return command
}

func (command Command) Cancel(actor, reason string, now time.Time) Command {
	if command.terminal() {
		return command
	}
	command.Status = CommandCanceled
	command.CanceledAt = now
	command.UpdatedAt = now
	if strings.TrimSpace(actor) != "" {
		command.Actor = strings.TrimSpace(actor)
	}
	if strings.TrimSpace(reason) != "" {
		command.Error = reason
	}
	return command
}

func (command Command) Retry(actor, reason string, now time.Time) Command {
	if command.Status == CommandApplied {
		return command
	}
	command.Status = CommandPending
	command.UpdatedAt = now
	command.AckedAt, command.CanceledAt, command.ExpiredAt = time.Time{}, time.Time{}, time.Time{}
	command.AckStatus, command.AckMessage = "", ""
	command.AckPolicyID, command.AckPolicyVer, command.AckReport, command.Error = "", 0, "", ""
	if strings.TrimSpace(actor) != "" {
		command.Actor = strings.TrimSpace(actor)
	}
	if strings.TrimSpace(reason) != "" {
		command.Reason = reason
	}
	return command
}

func (command Command) Expire(reason string, now time.Time) Command {
	if command.terminal() {
		return command
	}
	command.Status = CommandExpired
	command.ExpiredAt = now
	command.UpdatedAt = now
	if strings.TrimSpace(reason) != "" {
		command.Error = reason
	}
	return command
}

func (command Command) terminal() bool {
	switch command.Status {
	case CommandApplied, CommandRejected, CommandFailed, CommandCanceled, CommandExpired:
		return true
	default:
		return false
	}
}

func acknowledgementStatus(status CommandStatus) CommandStatus {
	switch status {
	case "", CommandApplied, "accepted", "validated", "degraded":
		return CommandApplied
	case CommandRejected:
		return CommandRejected
	case CommandFailed:
		return CommandFailed
	default:
		return status
	}
}

type EvidenceStatus string

const (
	EvidencePending   EvidenceStatus = "pending"
	EvidenceCompleted EvidenceStatus = "completed"
	EvidenceFailed    EvidenceStatus = "failed"
)

type EvidencePullback struct {
	ID          string
	TenantID    tenant.ID
	AgentID     string
	IncidentID  string
	Labels      map[string]string
	Target      string
	Reason      string
	Status      EvidenceStatus
	ResultOK    bool
	Result      string
	Evidence    []byte
	Actor       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CompletedAt time.Time
}

type EvidenceResult struct {
	TenantID tenant.ID
	AgentID  string
	OK       bool
	Message  string
	Evidence []byte
}

func NewEvidencePullback(value EvidencePullback, now time.Time) (EvidencePullback, error) {
	if strings.TrimSpace(value.ID) == "" || value.TenantID.IsZero() || strings.TrimSpace(value.AgentID) == "" {
		return EvidencePullback{}, failure.New(failure.InvalidArgument, "evidence pullback identity is required")
	}
	value.ID = strings.TrimSpace(value.ID)
	value.AgentID = strings.TrimSpace(value.AgentID)
	value.Labels = cloneLabels(value.Labels)
	value.Status = EvidencePending
	value.CreatedAt = now.UTC()
	value.UpdatedAt = now.UTC()
	return value, nil
}

type AuditRecord struct {
	ID         string
	TenantID   tenant.ID
	ResourceID string
	Action     string
	Actor      string
	Reason     string
	Status     string
	OccurredAt time.Time
}

func (pullback EvidencePullback) Complete(result EvidenceResult, observedAt time.Time) (EvidencePullback, error) {
	if pullback.TenantID != result.TenantID || pullback.AgentID != result.AgentID {
		return EvidencePullback{}, failure.New(failure.Conflict, "evidence pullback identity mismatch")
	}
	status := EvidenceFailed
	if result.OK {
		status = EvidenceCompleted
	}
	if pullback.Status != EvidencePending {
		if pullback.Status == status && pullback.ResultOK == result.OK && pullback.Result == result.Message &&
			equalEvidence(pullback.Evidence, result.Evidence) {
			return pullback, nil
		}
		return EvidencePullback{}, failure.New(failure.Conflict, "evidence pullback already completed")
	}
	pullback.Status = status
	pullback.ResultOK = result.OK
	pullback.Result = result.Message
	pullback.Evidence = append([]byte(nil), result.Evidence...)
	pullback.UpdatedAt = observedAt
	pullback.CompletedAt = observedAt
	return pullback, nil
}

func equalEvidence(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}
