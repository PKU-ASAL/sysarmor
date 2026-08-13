package policy

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/audit"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func Publish(current, candidate Policy, actor tenant.Actor, now time.Time) (Policy, audit.Record, error) {
	if err := actor.Require(tenant.RoleOperator); err != nil {
		return Policy{}, audit.Record{}, err
	}
	if current.TenantID != actor.TenantID || candidate.TenantID != actor.TenantID {
		return Policy{}, audit.Record{}, failure.New(failure.PermissionDenied, "policy tenant does not match actor tenant")
	}
	if current.ID != candidate.ID || candidate.ID == "" || candidate.Version == 0 {
		return Policy{}, audit.Record{}, failure.New(failure.InvalidArgument, "policy identity is invalid")
	}
	if candidate.Version < current.Version {
		return Policy{}, audit.Record{}, failure.New(failure.Conflict, "policy version is stale")
	}
	published := clonePolicy(candidate)
	published.UpdatedAt = now
	action := "policy.unpublish"
	if published.Published {
		action = "policy.publish"
	}
	return published, audit.Record{
		TenantID:      published.TenantID,
		Action:        action,
		PolicyID:      published.ID.String(),
		PolicyVersion: uint64(published.Version),
		Actor:         actor.Subject,
		Status:        "success",
		OccurredAt:    now,
	}, nil
}

func (id ID) String() string { return string(id) }

func clonePolicy(value Policy) Policy {
	value.Document = append([]byte(nil), value.Document...)
	value.DownlinkDocument = append([]byte(nil), value.DownlinkDocument...)
	return value
}
