package response

import (
	"context"
	"fmt"
	"strings"
	"time"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type Controller interface {
	Execute(context.Context, domainresponse.Command) domainresponse.Ack
	CollectEvidence(context.Context, EvidenceRequest) EvidenceResult
}

type EvidenceRequest struct {
	RequestID string
	Target    string
}

type EvidenceResult struct {
	RequestID  string
	TenantID   string
	AgentID    string
	OK         bool
	Message    string
	Evidence   domainresponse.EvidenceSubgraph
	ObservedAt time.Time
}

type Service struct {
	context  ports.ResponseContext
	executor ports.ResponseExecutor
}

func NewService(responseContext ports.ResponseContext, executor ports.ResponseExecutor) *Service {
	return &Service{context: responseContext, executor: executor}
}

func (s *Service) Execute(ctx context.Context, command domainresponse.Command) domainresponse.Ack {
	command = domainresponse.Normalize(command)
	identity := s.context.Identity()
	policy := s.context.Policy()
	runtimeScope, known := s.context.Scope()
	auth := domainresponse.AuthorizationContext{
		TenantID: identity.TenantID, AgentID: identity.AgentID,
		RuntimeScope: runtimeScope, ScopeKnown: known,
	}
	if decision := domainresponse.Authorize(command, policy, auth); !decision.Allowed {
		return unsupported(command.ID, identity, decision.Reason)
	}
	if command.Mode == domainresponse.ModeObserve {
		return domainresponse.Ack{
			ResponseID: command.ID, TenantID: identity.TenantID, AgentID: identity.AgentID,
			Accepted: true, ObserveOnly: true, ObservedAt: time.Now().UTC(),
			Message: fmt.Sprintf("observe-only response accepted; would execute action=%s target=%s", command.Action, command.Target),
		}
	}
	execution := ports.ResponseExecution{ID: command.ID, Action: command.Action, Target: command.Target, Reason: command.Reason}
	ack, err := s.executor.Enforce(ctx, execution)
	if err != nil {
		return unsupported(command.ID, identity, err.Error())
	}
	return domainresponse.Ack{
		ResponseID: command.ID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Accepted: ack.Accepted, Unsupported: ack.Unsupported,
		ObserveOnly: ack.ObserveOnly, Executed: ack.Accepted && !ack.Unsupported && !ack.ObserveOnly,
		Message: ack.Message, ObservedAt: time.Now().UTC(),
	}
}

func (s *Service) CollectEvidence(_ context.Context, request EvidenceRequest) EvidenceResult {
	identity := s.context.Identity()
	result := EvidenceResult{
		RequestID: request.RequestID, TenantID: identity.TenantID, AgentID: identity.AgentID,
		OK: true, Message: "collected target evidence", ObservedAt: time.Now().UTC(),
	}
	if request.Target == "" {
		result.Message = "collected no target evidence"
		return result
	}
	result.Evidence.Nodes = []domainresponse.EvidenceNode{{
		ID: request.Target, Kind: evidenceKind(request.Target), Label: request.Target,
	}}
	return result
}

func unsupported(id string, identity ports.ResponseIdentity, message string) domainresponse.Ack {
	return domainresponse.Ack{
		ResponseID: id, TenantID: identity.TenantID, AgentID: identity.AgentID,
		Unsupported: true, Message: message, ObservedAt: time.Now().UTC(),
	}
}

func evidenceKind(target string) string {
	if index := strings.Index(target, ":"); index > 0 {
		return target[:index]
	}
	return "entity"
}
