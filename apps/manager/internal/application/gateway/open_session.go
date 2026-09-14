package gateway

import (
	"context"
	"fmt"
	"strings"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type OpenSessionService struct {
	repository ports.ControlSessionRepository
	delivery   ports.ControlDelivery
}

func NewOpenSessionService(repository ports.ControlSessionRepository, delivery ports.ControlDelivery) *OpenSessionService {
	return &OpenSessionService{repository: repository, delivery: delivery}
}

func (service *OpenSessionService) Open(ctx context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(agentID) == "" {
		return domaingateway.OpenSession{}, fmt.Errorf("control session tenant and agent are required")
	}
	if service == nil || service.repository == nil || service.delivery == nil {
		return domaingateway.OpenSession{}, fmt.Errorf("control session repository and delivery are required")
	}
	result, err := service.repository.Open(ctx, tenantID, agentID, scopeType, scopeSelector)
	if err != nil {
		return domaingateway.OpenSession{}, err
	}
	if err := markControlMessagesSent(ctx, service.delivery, tenantID, agentID, result.Messages); err != nil {
		return domaingateway.OpenSession{}, err
	}
	return result, nil
}
