package store

import (
	"context"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type SessionRepository struct{ store *Store }

func NewSessionRepository(store *Store) SessionRepository { return SessionRepository{store: store} }
func (reader SessionRepository) List(_ context.Context, tenantID tenant.ID, filter domainidentity.SessionFilter) ([]domainidentity.Session, error) {
	reader.store.mu.RLock()
	defer reader.store.mu.RUnlock()
	result := make([]domainidentity.Session, 0)
	for _, value := range reader.store.AgentSessions {
		if value.TenantID != tenantID.String() || filter.AgentID != "" && value.AgentID != filter.AgentID {
			continue
		}
		result = append(result, domainidentity.Session{TenantID: tenantID, ID: value.SessionID, AgentID: domainidentity.AgentID(value.AgentID), StartedAt: value.StartedAt, LastSeenAt: value.LastSeenAt, LastDataSeenAt: value.LastDataSeenAt, LastControlSeenAt: value.LastControlSeenAt, ClosedAt: value.ClosedAt, LastAckCursor: value.LastAckCursor, DataTransport: value.DataTransport, ControlTransport: value.ControlTransport, Status: value.Status})
	}
	return result, nil
}

type RarityReader struct{ store *Store }

func NewRarityReader(store *Store) RarityReader { return RarityReader{store: store} }
func (reader RarityReader) Rarity(_ context.Context, tenantID tenant.ID) (domainidentity.RarityBaseline, error) {
	reader.store.mu.RLock()
	defer reader.store.mu.RUnlock()
	return domainidentity.RarityBaseline{WorkloadCounts: reader.store.RarityByTenant[tenantID.String()].Snapshot().WorkloadCounts}, nil
}
