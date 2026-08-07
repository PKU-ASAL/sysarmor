package control

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

func (c *EnrollmentCoordinator) Enroll(ctx context.Context, command EnrollmentCommand) Result {
	if c.store == nil {
		return c.result(command.Context, "rejected", "local store is unavailable")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if result, handled := c.existingEnrollment(ctx, command.Context); handled {
		return result
	}
	managerURL, err := normalizeEnrollmentManagerURL(command.ManagerURL)
	if err != nil {
		return c.result(command.Context, "rejected", err.Error())
	}
	preparation, err := c.runtime.PrepareEnrollment(ctx, managerURL, command.Token)
	if err != nil {
		return c.result(command.Context, "rejected", err.Error())
	}
	return c.commitEnrollment(ctx, command, preparation)
}

func (c *EnrollmentCoordinator) commitEnrollment(ctx context.Context, command EnrollmentCommand, preparation EnrollmentPreparation) Result {
	stats, err := c.store.Stats(ctx)
	if err != nil {
		return c.rollbackEnrollment(command.Context, preparation, err)
	}
	enrollment := preparation.Enrollment
	enrollment.UploadHistory = command.UploadHistory
	enrollment.ManagedFromSequence = stats.LatestEventSequence + 1
	if command.UploadHistory {
		enrollment.ManagedFromSequence = stats.OldestEventSequence
	}
	c.runtime.StopEnrollmentNetwork()
	committed := false
	err = c.runtime.WithPolicyAuthority(func() error {
		if err := c.store.SetEnrolling(ctx, enrollment); err != nil {
			return err
		}
		committed = true
		return c.runtime.ReconcileEnrollment(enrollment)
	})
	if err != nil {
		if committed {
			c.runtime.FinalizeEnrollment(preparation)
			return c.result(command.Context, "pending", "enrollment committed; runtime reconciliation is pending: "+err.Error())
		}
		if reconcileErr := c.runtime.ReconcileEnrollment(localstore.Enrollment{State: localstore.StateStandalone}); reconcileErr != nil {
			err = fmt.Errorf("%w; restore standalone runtime: %v", err, reconcileErr)
		}
		return c.rollbackEnrollment(command.Context, preparation, err)
	}
	c.runtime.FinalizeEnrollment(preparation)
	return c.result(command.Context, "pending", "enrollment credentials accepted; waiting for manager endpoint policy")
}

func (c *EnrollmentCoordinator) rollbackEnrollment(request RequestContext, preparation EnrollmentPreparation, cause error) Result {
	if err := c.runtime.RollbackEnrollment(preparation, cause); err != nil {
		cause = err
	}
	return c.result(request, "rejected", cause.Error())
}

func (c *EnrollmentCoordinator) existingEnrollment(ctx context.Context, request RequestContext) (Result, bool) {
	enrollment, err := c.store.Enrollment(ctx)
	if err != nil {
		return c.result(request, "rejected", "read enrollment state: "+err.Error()), true
	}
	switch enrollment.State {
	case localstore.StateStandalone:
		return c.existingStandaloneEnrollment(ctx, request)
	case localstore.StateEnrolling:
		return c.result(request, "pending", "enrollment is already waiting for manager endpoint policy"), true
	case localstore.StateManaged:
		return c.result(request, "rejected", "agent is already managed"), true
	case localstore.StateUnenrolling:
		return c.result(request, "rejected", "agent unenrollment is pending manager confirmation"), true
	default:
		return c.result(request, "rejected", "unsupported enrollment state"), true
	}
}

func (c *EnrollmentCoordinator) existingStandaloneEnrollment(ctx context.Context, request RequestContext) (Result, bool) {
	_, pending, err := c.store.UnenrollmentCompletion(ctx)
	if err != nil {
		return c.result(request, "rejected", "read unenrollment completion: "+err.Error()), true
	}
	if pending {
		return c.result(request, "pending", "manager unenrollment completion is pending acknowledgement"), true
	}
	return Result{}, false
}

func normalizeEnrollmentManagerURL(base string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("manager_url must be an absolute HTTP(S) URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}
