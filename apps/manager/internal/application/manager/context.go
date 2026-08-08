package manager

import "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"

type RequestContext struct {
	Actor tenant.Actor
}
