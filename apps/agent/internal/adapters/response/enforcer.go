package response

import (
	"context"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Backend interface {
	Enforce(context.Context, contract.EnforcementCmd) (contract.EnforcementAck, error)
}

type Enforcer struct {
	backend Backend
}

func NewEnforcer(backend Backend) *Enforcer {
	return &Enforcer{backend: backend}
}

func (e *Enforcer) Enforce(ctx context.Context, command ports.ResponseExecution) (ports.ResponseExecutionAck, error) {
	ack, err := e.backend.Enforce(ctx, contract.EnforcementCmd{
		ID: command.ID, Action: command.Action, Target: command.Target, Reason: command.Reason,
	})
	return ports.ResponseExecutionAck{
		ID: ack.ID, Accepted: ack.Accepted, Unsupported: ack.Unsupported,
		ObserveOnly: ack.ObserveOnly, Message: ack.Message,
	}, err
}
