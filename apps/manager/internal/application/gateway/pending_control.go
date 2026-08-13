package gateway

import (
	"context"
	"fmt"
	"strings"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type PendingControlService struct {
	messages ports.ControlMessageRepository
	delivery ports.ControlDelivery
}

func NewPendingControlService(messages ports.ControlMessageRepository, delivery ports.ControlDelivery) *PendingControlService {
	return &PendingControlService{messages: messages, delivery: delivery}
}

func (service *PendingControlService) Pull(ctx context.Context, tenantID, agentID string) ([]domaingateway.Message, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("control message tenant and agent are required")
	}
	if service == nil || service.messages == nil || service.delivery == nil {
		return nil, fmt.Errorf("control message repository and delivery are required")
	}
	messages, err := service.messages.Pending(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	if err := markControlMessagesSent(ctx, service.delivery, tenantID, agentID, messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func markControlMessagesSent(ctx context.Context, delivery ports.ControlDelivery, tenantID, agentID string, messages []domaingateway.Message) error {
	for _, message := range messages {
		if message.Type != "control_command" {
			continue
		}
		if err := delivery.MarkSent(ctx, tenantID, agentID, message.ID); err != nil {
			return fmt.Errorf("mark control command sent: %w", err)
		}
	}
	return nil
}
