package audit

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type Record struct {
	ID            string
	TenantID      tenant.ID
	Action        string
	PolicyID      string
	PolicyVersion uint64
	AssignmentID  string
	Actor         string
	Reason        string
	Status        string
	OccurredAt    time.Time
}
