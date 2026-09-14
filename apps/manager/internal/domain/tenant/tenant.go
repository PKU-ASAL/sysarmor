package tenant

import (
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type ID string

func NewID(raw string) (ID, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", failure.New(failure.InvalidArgument, "tenant is required")
	}
	return ID(value), nil
}

func (id ID) String() string { return string(id) }

func (id ID) IsZero() bool { return strings.TrimSpace(id.String()) == "" }

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type RoleSet struct {
	bits uint8
}

func NewRoleSet(roles ...Role) RoleSet {
	var set RoleSet
	for _, role := range roles {
		set.bits |= roleBit(role)
	}
	return set
}

func (set RoleSet) Has(role Role) bool {
	const (
		viewerBit   = 1
		operatorBit = 2
		adminBit    = 4
	)
	switch role {
	case RoleViewer:
		return set.bits&(viewerBit|operatorBit|adminBit) != 0
	case RoleOperator:
		return set.bits&(operatorBit|adminBit) != 0
	case RoleAdmin:
		return set.bits&adminBit != 0
	default:
		return false
	}
}

func roleBit(role Role) uint8 {
	switch role {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 4
	default:
		return 0
	}
}

type Actor struct {
	Subject  string
	TenantID ID
	Roles    RoleSet
}

func (actor Actor) Require(role Role) error {
	if actor.TenantID.IsZero() {
		return failure.New(failure.Unauthenticated, "tenant is required")
	}
	if actor.Roles.Has(role) {
		return nil
	}
	return failure.New(failure.PermissionDenied, "required role is not granted")
}
