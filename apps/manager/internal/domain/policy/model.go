package policy

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type ID string
type Version uint64

const DefaultPolicyID ID = "default-edr-policy"

type Policy struct {
	TenantID  tenant.ID
	ID        ID
	Version   Version
	Published bool
	CreatedAt time.Time
	UpdatedAt time.Time
	Document  []byte
}

type Target struct {
	AgentID       string
	ScopeType     string
	ScopeSelector string
}

type Assignment struct {
	ID            string
	TenantID      tenant.ID
	Target        Target
	PolicyID      ID
	PolicyVersion Version
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Filter struct {
	PolicyID ID
}

type AssignmentFilter struct {
	AgentID string
}
