package session

import (
	"context"
	"fmt"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type QueryService struct{ sessions ports.AgentSessionRepository }

type ResumeResult struct{ SessionID, Cursor string }

func NewQueryService(sessions ports.AgentSessionRepository) *QueryService {
	return &QueryService{sessions: sessions}
}

func (service *QueryService) Resume(ctx context.Context, tenantValue, agentID string) (ResumeResult, error) {
	sessions, err := service.list(ctx, tenantValue, agentID)
	if err != nil || len(sessions) == 0 {
		return ResumeResult{}, err
	}
	return ResumeResult{SessionID: sessions[0].ID, Cursor: sessions[0].LastAckCursor}, nil
}

func (service *QueryService) IsDuplicate(ctx context.Context, tenantValue, agentID, cursor string) (bool, error) {
	if cursor == "" {
		return false, nil
	}
	sessions, err := service.list(ctx, tenantValue, agentID)
	if err != nil {
		return false, err
	}
	for _, value := range sessions {
		if value.LastAckCursor == cursor {
			return true, nil
		}
	}
	return false, nil
}

func (service *QueryService) list(ctx context.Context, tenantValue, agentID string) ([]domainidentity.Session, error) {
	tenantID, err := tenant.NewID(tenantValue)
	if err != nil {
		return nil, err
	}
	if service == nil || service.sessions == nil {
		return nil, fmt.Errorf("session repository is required")
	}
	return service.sessions.List(ctx, tenantID, domainidentity.SessionFilter{AgentID: agentID})
}
