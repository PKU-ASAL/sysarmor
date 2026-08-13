package ports

import (
	"context"

	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type ControlRepository interface {
	Get(context.Context, tenant.ID, string) (domaincontrol.Command, error)
	List(context.Context, tenant.ID, ControlFilter) ([]domaincontrol.Command, error)
	Create(context.Context, domaincontrol.Command) (domaincontrol.Command, error)
	Put(context.Context, domaincontrol.Command, domaincontrol.Command) error
}

type ControlFilter struct {
	AgentID string
	Type    domaincontrol.CommandType
}

type EvidenceRepository interface {
	Get(context.Context, tenant.ID, string) (domaincontrol.EvidencePullback, error)
	List(context.Context, tenant.ID, EvidenceFilter) ([]domaincontrol.EvidencePullback, error)
	Create(context.Context, domaincontrol.EvidencePullback) (domaincontrol.EvidencePullback, error)
	Put(context.Context, domaincontrol.EvidencePullback, domaincontrol.EvidencePullback) error
}

type EvidenceFilter struct{ AgentID string }

type ControlAuditRepository interface {
	Append(context.Context, domaincontrol.AuditRecord) error
}

type ControlTransaction interface {
	Commands() ControlRepository
	Evidence() EvidenceRepository
	Audits() ControlAuditRepository
}

type ControlUnitOfWork interface {
	Execute(context.Context, func(context.Context, ControlTransaction) error) error
}
