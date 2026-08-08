package policy

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func Save(current, candidate Policy, actor tenant.Actor, now time.Time) (Policy, audit.Record, error) {
	if err := actor.Require(tenant.RoleAdmin); err != nil {
		return Policy{}, audit.Record{}, err
	}
	if candidate.TenantID != actor.TenantID || !current.TenantID.IsZero() && current.TenantID != actor.TenantID {
		return Policy{}, audit.Record{}, failure.New(failure.PermissionDenied, "policy tenant does not match actor tenant")
	}
	if candidate.ID == "" || candidate.Version == 0 || current.ID != "" && current.ID != candidate.ID {
		return Policy{}, audit.Record{}, failure.New(failure.InvalidArgument, "policy identity is invalid")
	}
	if current.Version > candidate.Version {
		return Policy{}, audit.Record{}, failure.New(failure.Conflict, "policy version is stale")
	}
	saved := clonePolicy(candidate)
	if saved.CreatedAt.IsZero() {
		saved.CreatedAt = current.CreatedAt
		if saved.CreatedAt.IsZero() {
			saved.CreatedAt = now
		}
	}
	saved.UpdatedAt = now
	return saved, audit.Record{
		TenantID: saved.TenantID, Action: "policy.upsert", PolicyID: saved.ID.String(),
		PolicyVersion: uint64(saved.Version), Actor: actor.Subject, Status: "success", OccurredAt: now,
	}, nil
}
