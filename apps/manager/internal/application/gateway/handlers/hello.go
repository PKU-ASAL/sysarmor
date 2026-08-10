package handlers

import (
	"context"
	"fmt"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type HelloHandler struct {
	sessions *gatewayapp.OpenSessionService
}

func NewHelloHandler(sessions *gatewayapp.OpenSessionService) HelloHandler {
	return HelloHandler{sessions: sessions}
}

func (handler HelloHandler) Handle(ctx context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
	if handler.sessions == nil {
		return ports.ControlResult{}, fmt.Errorf("control session service is required")
	}
	hello, _ := frame.Payload.(domaingateway.Hello)
	state, err := handler.sessions.Open(ctx, frame.TenantID, frame.AgentID, hello.ScopeType, hello.ScopeSelector)
	if err != nil {
		return ports.ControlResult{}, err
	}
	frames := []ports.ControlFrame{
		{Type: "policy_update", RequestID: "policy-" + frame.RequestID, Payload: state.PolicyDocument},
		{Type: "resume", RequestID: frame.RequestID, Payload: state},
	}
	for _, message := range state.Messages {
		frames = append(frames, ports.ControlFrame{Type: message.Type, RequestID: message.ID, Payload: message})
	}
	return ports.ControlResult{Frames: frames}, nil
}
