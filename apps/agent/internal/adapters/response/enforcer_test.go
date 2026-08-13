package response

import (
	"context"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type recordingBackend struct {
	command contract.EnforcementCmd
}

func (b *recordingBackend) Enforce(_ context.Context, command contract.EnforcementCmd) (contract.EnforcementAck, error) {
	b.command = command
	return contract.EnforcementAck{ID: command.ID, Accepted: true, ObserveOnly: true, Message: "executed"}, nil
}

func TestEnforcerMapsTypedExecutionContract(t *testing.T) {
	backend := &recordingBackend{}
	ack, err := NewEnforcer(backend).Enforce(t.Context(), ports.ResponseExecution{
		ID: "response-a", Action: "kill", Target: "process:42", Reason: "contain",
	})
	if err != nil || ack.ID != "response-a" || !ack.Accepted || !ack.ObserveOnly || ack.Message != "executed" {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	if backend.command.Action != "kill" || backend.command.Target != "process:42" || backend.command.Reason != "contain" {
		t.Fatalf("command=%+v", backend.command)
	}
}
