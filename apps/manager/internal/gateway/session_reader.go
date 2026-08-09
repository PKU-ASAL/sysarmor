package gateway

import (
	"context"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type storeSessionRepository struct{ store *store.Store }

func (reader storeSessionRepository) List(_ context.Context, tenantID tenant.ID, filter domainidentity.SessionFilter) ([]domainidentity.Session, error) {
	values, err := reader.store.ListAgentSessionsWithError(tenantID.String(), filter.AgentID)
	if err != nil {
		return nil, err
	}
	result := make([]domainidentity.Session, 0, len(values))
	for _, value := range values {
		result = append(result, domainidentity.Session{TenantID: tenantID, ID: value.SessionID, AgentID: domainidentity.AgentID(value.AgentID), LastAckCursor: value.LastAckCursor})
	}
	return result, nil
}
