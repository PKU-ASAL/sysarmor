package enrollment

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

func (s *Service) Enroll(ctx context.Context, command EnrollmentCommand) lifecycle.Result {
	if s.store == nil {
		return s.result(command.Context, lifecycle.StatusRejected, "local store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if result, handled := s.existingEnrollment(ctx, command.Context); handled {
		return result
	}
	managerURL, err := normalizeManagerURL(command.ManagerURL)
	if err != nil {
		return s.result(command.Context, lifecycle.StatusRejected, err.Error())
	}
	preparation, err := s.runtime.PrepareEnrollment(ctx, managerURL, command.Token)
	if err != nil {
		return s.result(command.Context, lifecycle.StatusRejected, err.Error())
	}
	return s.commitEnrollment(s.lifecycleCtx, command, preparation)
}

func (s *Service) commitEnrollment(ctx context.Context, command EnrollmentCommand, preparation ports.EnrollmentPreparation) lifecycle.Result {
	stats, err := s.store.Stats(ctx)
	if err != nil {
		return s.rollbackEnrollment(command.Context, preparation, err)
	}
	enrollment := preparation.PreparedEnrollment()
	enrollment.UploadHistory = command.UploadHistory
	enrollment.ManagedFromSequence = stats.LatestEventSequence + 1
	if command.UploadHistory {
		enrollment.ManagedFromSequence = stats.OldestEventSequence
	}
	s.runtime.StopEnrollmentNetwork()
	return s.commitEnrollmentState(ctx, command.Context, enrollment, preparation)
}

func (s *Service) commitEnrollmentState(ctx context.Context, request lifecycle.RequestContext, enrollment ports.Enrollment, preparation ports.EnrollmentPreparation) lifecycle.Result {
	committed := false
	err := s.runtime.WithPolicyAuthority(func() error {
		if err := s.store.SetEnrolling(ctx, enrollment); err != nil {
			return err
		}
		committed = true
		return s.runtime.ReconcileEnrollment(enrollment)
	})
	if err == nil {
		message := "enrollment credentials accepted; waiting for manager endpoint policy"
		if finalizeErr := s.runtime.FinalizeEnrollment(preparation); finalizeErr != nil {
			message += "; finalize enrollment: " + finalizeErr.Error()
		}
		return s.result(request, lifecycle.StatusPending, message)
	}
	return s.failedEnrollmentCommit(request, preparation, committed, err)
}

func (s *Service) failedEnrollmentCommit(request lifecycle.RequestContext, preparation ports.EnrollmentPreparation, committed bool, cause error) lifecycle.Result {
	if committed {
		message := "enrollment committed; runtime reconciliation is pending: " + cause.Error()
		if finalizeErr := s.runtime.FinalizeEnrollment(preparation); finalizeErr != nil {
			message += "; finalize enrollment: " + finalizeErr.Error()
		}
		return s.result(request, lifecycle.StatusPending, message)
	}
	standalone := ports.Enrollment{State: management.StateStandalone}
	if err := s.runtime.ReconcileEnrollment(standalone); err != nil {
		cause = fmt.Errorf("%w; restore standalone runtime: %v", cause, err)
	}
	return s.rollbackEnrollment(request, preparation, cause)
}

func (s *Service) rollbackEnrollment(request lifecycle.RequestContext, preparation ports.EnrollmentPreparation, cause error) lifecycle.Result {
	if err := s.runtime.RollbackEnrollment(preparation, cause); err != nil {
		cause = err
	}
	return s.result(request, lifecycle.StatusRejected, cause.Error())
}

func (s *Service) existingEnrollment(ctx context.Context, request lifecycle.RequestContext) (lifecycle.Result, bool) {
	enrollment, err := s.store.Enrollment(ctx)
	if err != nil {
		return s.result(request, lifecycle.StatusRejected, "read enrollment state: "+err.Error()), true
	}
	switch enrollment.State {
	case management.StateStandalone:
		return s.existingStandaloneEnrollment(ctx, request)
	case management.StateEnrolling:
		return s.result(request, lifecycle.StatusPending, "enrollment is already waiting for manager endpoint policy"), true
	case management.StateManaged:
		return s.result(request, lifecycle.StatusRejected, "agent is already managed"), true
	case management.StateUnenrolling:
		return s.result(request, lifecycle.StatusRejected, "agent unenrollment is pending manager confirmation"), true
	default:
		return s.result(request, lifecycle.StatusRejected, "unsupported enrollment state"), true
	}
}

func (s *Service) existingStandaloneEnrollment(ctx context.Context, request lifecycle.RequestContext) (lifecycle.Result, bool) {
	_, pending, err := s.store.UnenrollmentCompletion(ctx)
	if err != nil {
		return s.result(request, lifecycle.StatusRejected, "read unenrollment completion: "+err.Error()), true
	}
	if pending {
		return s.result(request, lifecycle.StatusPending, "manager unenrollment completion is pending acknowledgement"), true
	}
	return lifecycle.Result{}, false
}

func normalizeManagerURL(base string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("manager_url must be an absolute HTTP(S) URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}
