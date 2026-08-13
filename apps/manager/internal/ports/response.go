package ports

import (
	"context"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type ResponseFilter struct {
	AgentID string
	Pending bool
}

type ResponseRepository interface {
	Get(context.Context, tenant.ID, string) (domainresponse.Command, error)
	List(context.Context, tenant.ID, ResponseFilter) ([]domainresponse.Command, error)
	Create(context.Context, domainresponse.Command) (domainresponse.Command, error)
	Put(context.Context, domainresponse.Command, domainresponse.Command) error
}

type ResponseAuditRepository interface {
	Append(context.Context, domainresponse.AuditRecord) error
}

type ResponseTransaction interface {
	Responses() ResponseRepository
	Audits() ResponseAuditRepository
}

type ResponseUnitOfWork interface {
	Execute(context.Context, func(context.Context, ResponseTransaction) error) error
}
