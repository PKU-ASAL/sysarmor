package policy

import (
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func Assign(value Policy, target Target, actor tenant.Actor, now time.Time) (Assignment, error) {
	if err := actor.Require(tenant.RoleOperator); err != nil {
		return Assignment{}, err
	}
	if value.TenantID != actor.TenantID {
		return Assignment{}, failure.New(failure.PermissionDenied, "policy tenant does not match actor tenant")
	}
	if !value.Published {
		return Assignment{}, failure.New(failure.FailedPrecondition, "policy must be published before assignment")
	}
	if err := validateTarget(target); err != nil {
		return Assignment{}, err
	}
	return Assignment{
		TenantID:      value.TenantID,
		Target:        target,
		PolicyID:      value.ID,
		PolicyVersion: value.Version,
		CreatedAt:     now,
		UpdatedAt:     now,
	}, nil
}

func validateTarget(target Target) error {
	hasAgent := strings.TrimSpace(target.AgentID) != ""
	hasScopeType := strings.TrimSpace(target.ScopeType) != ""
	hasScopeSelector := strings.TrimSpace(target.ScopeSelector) != ""
	if hasAgent && (hasScopeType || hasScopeSelector) {
		return failure.New(failure.InvalidArgument, "policy assignment must target either an agent or a scope")
	}
	if !hasAgent && !hasScopeType && !hasScopeSelector {
		return failure.New(failure.InvalidArgument, "policy assignment target is required")
	}
	if hasScopeSelector && !hasScopeType {
		return failure.New(failure.InvalidArgument, "policy assignment scope type is required")
	}
	return nil
}
