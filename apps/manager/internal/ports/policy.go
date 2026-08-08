package ports

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type PolicyRepository interface {
	Get(context.Context, tenant.ID, domainpolicy.ID, domainpolicy.Version) (domainpolicy.Policy, error)
	Current(context.Context, tenant.ID, domainpolicy.ID) (domainpolicy.Policy, error)
	Published(context.Context, tenant.ID, domainpolicy.ID, domainpolicy.Version) (domainpolicy.Policy, error)
	List(context.Context, tenant.ID, domainpolicy.Filter) ([]domainpolicy.Policy, error)
	Put(context.Context, domainpolicy.Policy) error
}

type AssignmentRepository interface {
	Candidates(context.Context, tenant.ID, domainpolicy.Target) ([]domainpolicy.Assignment, error)
	List(context.Context, tenant.ID, domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error)
	Put(context.Context, domainpolicy.Assignment) error
}

type PolicyControlCommand struct {
	ID            string
	TenantID      tenant.ID
	AgentID       string
	PolicyID      domainpolicy.ID
	PolicyVersion domainpolicy.Version
	Payload       []byte
	Actor         string
	Reason        string
	CreatedAt     time.Time
}

type PolicyControlRepository interface {
	Put(context.Context, PolicyControlCommand) error
}

type AuditRepository interface {
	Append(context.Context, tenant.ID, audit.Record) error
	List(context.Context, tenant.ID, domainpolicy.ID) ([]audit.Record, error)
}

type PolicyTransaction interface {
	Policies() PolicyRepository
	Assignments() AssignmentRepository
	Controls() PolicyControlRepository
	Audits() AuditRepository
}

type PolicyUnitOfWork interface {
	Execute(context.Context, func(context.Context, PolicyTransaction) error) error
}
