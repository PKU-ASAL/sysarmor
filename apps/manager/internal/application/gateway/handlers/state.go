package handlers

import (
	"context"
	"fmt"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type StateHandler struct {
	kind   string
	writer ports.ControlStateWriter
}

func NewStateHandler(kind string, writer ports.ControlStateWriter) StateHandler {
	return StateHandler{kind: kind, writer: writer}
}
func (handler StateHandler) Handle(ctx context.Context, frame ports.ControlFrame) (ports.ControlResult, error) {
	if handler.writer == nil {
		return ports.ControlResult{}, fmt.Errorf("control state writer is required")
	}
	err := handler.write(ctx, frame)
	if err != nil {
		return ports.ControlResult{}, err
	}
	ack := domaingateway.Ack{Status: "accepted"}
	return ports.ControlResult{Frames: []ports.ControlFrame{{Type: "ack", RequestID: frame.RequestID, Payload: ack}}}, nil
}
func (handler StateHandler) write(ctx context.Context, frame ports.ControlFrame) error {
	switch handler.kind {
	case "health_report":
		value, ok := frame.Payload.(domainidentity.Health)
		if !ok {
			return fmt.Errorf("health payload is required")
		}
		return handler.writer.RecordHealth(ctx, value)
	case "capability_report":
		value, ok := frame.Payload.(domaingateway.Capability)
		if !ok {
			return fmt.Errorf("capability payload is required")
		}
		return handler.writer.RecordCapability(ctx, value)
	case "response_ack":
		value, ok := frame.Payload.(domaingateway.Ack)
		if !ok {
			return fmt.Errorf("response ack payload is required")
		}
		return handler.writer.AckResponse(ctx, value)
	case "ack":
		value, ok := frame.Payload.(domaingateway.Ack)
		if !ok {
			return fmt.Errorf("command ack payload is required")
		}
		return handler.writer.AckCommand(ctx, value)
	case "evidence_pullback_result":
		value, ok := frame.Payload.(domaingateway.EvidenceResult)
		if !ok {
			return fmt.Errorf("evidence result payload is required")
		}
		return handler.writer.CompleteEvidence(ctx, value)
	default:
		return fmt.Errorf("unsupported state handler %q", handler.kind)
	}
}
