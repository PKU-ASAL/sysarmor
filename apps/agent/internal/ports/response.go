package ports

import (
	"context"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
)

type ResponseIdentity struct {
	TenantID string
	AgentID  string
}

type ResponseExecution struct {
	ID     string
	Action string
	Target string
	Reason string
}

type ResponseExecutionAck struct {
	ID          string
	Accepted    bool
	Unsupported bool
	ObserveOnly bool
	Message     string
}

type ResponseContext interface {
	Identity() ResponseIdentity
	Policy() domainresponse.Policy
	Scope() (domainresponse.Scope, bool)
}

type ResponseExecutor interface {
	Enforce(context.Context, ResponseExecution) (ResponseExecutionAck, error)
}
