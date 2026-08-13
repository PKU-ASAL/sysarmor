package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

func (s *Service) Unenroll(ctx context.Context, command UnenrollmentCommand) lifecycle.Result {
	if s.store == nil {
		return s.result(command.Context, lifecycle.StatusRejected, "local store is unavailable")
	}
	s.mu.Lock()
	result, locallyComplete := s.unenrollLocked(ctx, command.Context)
	s.mu.Unlock()
	if !locallyComplete {
		return result
	}
	if _, err := s.runtime.ReportUnenrollmentCompletion(ctx); err != nil {
		message := "agent returned to standalone mode; manager completion is pending: " + err.Error()
		return s.result(command.Context, lifecycle.StatusPending, message)
	}
	return s.result(command.Context, lifecycle.StatusApplied, "manager confirmed endpoint unenrollment completion")
}

func (s *Service) unenrollLocked(ctx context.Context, request lifecycle.RequestContext) (lifecycle.Result, bool) {
	current, completion, err := s.prepareUnenrollment(ctx)
	if err != nil {
		return s.result(request, lifecycle.StatusRejected, err.Error()), false
	}
	if !current.RevocationConfirmed {
		receipt, revokedAt, err := s.runtime.RevokeEnrollment(ctx, current, completion.TokenHash)
		if err != nil {
			_ = s.store.RecordUnenrollmentError(ctx, err.Error())
			return s.result(request, lifecycle.StatusPending, "manager certificate revocation is pending: "+err.Error()), false
		}
		if err := s.store.ConfirmEnrollmentRevocation(s.lifecycleCtx, receipt, revokedAt); err != nil {
			return s.result(request, lifecycle.StatusRejected, err.Error()), false
		}
	}
	if err := s.completeConfirmed(s.lifecycleCtx, current); err != nil {
		return s.result(request, lifecycle.StatusRejected, err.Error()), false
	}
	if completion.TokenHash == "" {
		return s.result(request, lifecycle.StatusApplied, "manager revoked legacy enrollment; agent returned to standalone mode"), false
	}
	return lifecycle.Result{}, true
}

func (s *Service) Resume(ctx context.Context) error {
	if s.store == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.store.Enrollment(ctx)
	if err != nil {
		return fmt.Errorf("read enrollment for recovery: %w", err)
	}
	if current.State != management.StateUnenrolling || !current.RevocationConfirmed {
		return nil
	}
	return s.completeConfirmed(ctx, current)
}

func (s *Service) completeConfirmed(ctx context.Context, current ports.Enrollment) error {
	s.runtime.StopEnrollmentNetwork()
	if err := s.runtime.WithPolicyAuthority(func() error { return nil }); err != nil {
		return err
	}
	err := s.runtime.RestoreStandalonePolicy(ctx, func(ctx context.Context) error {
		if err := s.runtime.RemoveEnrollmentCredentials(current); err != nil {
			return err
		}
		return s.store.CompleteUnenrollment(ctx, "endpoint")
	})
	if err != nil {
		return err
	}
	return s.runtime.ReconcileEnrollment(ports.Enrollment{State: management.StateStandalone})
}

func (s *Service) prepareUnenrollment(ctx context.Context) (ports.Enrollment, ports.UnenrollmentCompletion, error) {
	token, tokenHash, err := newCompletionToken()
	if err != nil {
		return ports.Enrollment{}, ports.UnenrollmentCompletion{}, err
	}
	return s.store.PrepareUnenrollment(ctx, token, tokenHash)
}

func newCompletionToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate unenrollment completion token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}
