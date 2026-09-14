package ports

import (
	"context"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type AgentRepository interface {
	List(context.Context, tenant.ID, domainidentity.AgentFilter) ([]domainidentity.Agent, error)
}

type AgentHealthRepository interface {
	Get(context.Context, tenant.ID, domainidentity.AgentID) (domainidentity.Health, error)
	List(context.Context, tenant.ID, domainidentity.HealthFilter) ([]domainidentity.Health, error)
}

type AgentHealthWriter interface {
	Upsert(context.Context, domainidentity.Health) error
}

type AgentSessionRepository interface {
	List(context.Context, tenant.ID, domainidentity.SessionFilter) ([]domainidentity.Session, error)
}

type IdentitySnapshotRepository interface {
	Metrics(context.Context, tenant.ID) (domainidentity.Metrics, error)
	Rarity(context.Context, tenant.ID) (domainidentity.RarityBaseline, error)
}

type IdentityRepositories interface {
	Agents() AgentRepository
	Health() AgentHealthRepository
	Sessions() AgentSessionRepository
	Snapshots() IdentitySnapshotRepository
}
