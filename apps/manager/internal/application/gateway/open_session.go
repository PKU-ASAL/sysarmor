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
}

func NewOpenSessionService(repository ports.ControlSessionRepository) *OpenSessionService {
	return &OpenSessionService{repository: repository}
}

func (service *OpenSessionService) Open(ctx context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(agentID) == "" {
		return domaingateway.OpenSession{}, fmt.Errorf("control session tenant and agent are required")
	}
	if service == nil || service.repository == nil {
		return domaingateway.OpenSession{}, fmt.Errorf("control session repository is required")
	}
	return service.repository.Open(ctx, tenantID, agentID, scopeType, scopeSelector)
}
