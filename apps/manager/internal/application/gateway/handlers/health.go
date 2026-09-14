package handlers

import (
	"context"
	"fmt"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type HealthHandler struct {
	state   StateHandler
	pending *gatewayapp.PendingControlService
}

func NewHealthHandler(writer ports.ControlStateWriter, pending *gatewayapp.PendingControlService) HealthHandler {
	return HealthHandler{state: NewStateHandler("health_report", writer), pending: pending}
}

func (handler HealthHandler) Handle(ctx context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
	result, err := handler.state.Handle(ctx, frame)
	if err != nil {
		return ports.ControlResult{}, err
	}
	if handler.pending == nil {
		return ports.ControlResult{}, fmt.Errorf("pending control service is required")
	}
	messages, err := handler.pending.Pull(ctx, frame.TenantID, frame.AgentID)
	if err != nil {
		return ports.ControlResult{}, err
	}
	for _, message := range messages {
		result.Frames = append(result.Frames, ports.ControlFrame{Type: message.Type, RequestID: message.ID, Payload: message})
	}
	return result, nil
}
