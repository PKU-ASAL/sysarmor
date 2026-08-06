package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

func (c *EnrollmentCoordinator) Unenroll(ctx context.Context, command UnenrollmentCommand) Result {
	if c.store == nil {
		return c.result(command.Context, "rejected", "local store is unavailable")
	}
	c.mu.Lock()
	result, locallyComplete := c.unenrollLocked(ctx, command.Context)
	c.mu.Unlock()
	if !locallyComplete {
		return result
	}
	if _, err := c.runtime.ReportUnenrollmentCompletion(ctx); err != nil {
		message := "agent returned to standalone mode; manager completion is pending: " + err.Error()
		return c.result(command.Context, "pending", message)
	}
	return c.result(command.Context, "applied", "manager confirmed endpoint unenrollment completion")
}

func (c *EnrollmentCoordinator) unenrollLocked(ctx context.Context, request RequestContext) (Result, bool) {
	current, completion, err := c.prepareUnenrollment(ctx)
	if err != nil {
		return c.result(request, "rejected", err.Error()), false
	}
	if !current.RevocationConfirmed {
		receipt, revokedAt, err := c.runtime.RevokeEnrollment(ctx, current, completion.TokenHash)
		if err != nil {
			_ = c.store.RecordUnenrollmentError(ctx, err.Error())
			return c.result(request, "pending", "manager certificate revocation is pending: "+err.Error()), false
		}
		if err := c.store.ConfirmEnrollmentRevocation(ctx, receipt, revokedAt); err != nil {
			return c.result(request, "rejected", err.Error()), false
		}
	}
	if err := c.completeConfirmed(c.lifecycleCtx, current); err != nil {
		return c.result(request, "rejected", err.Error()), false
	}
	if completion.TokenHash == "" {
		return c.result(request, "applied", "manager revoked legacy enrollment; agent returned to standalone mode"), false
	}
	return Result{}, true
}

func (c *EnrollmentCoordinator) Resume(ctx context.Context) error {
	if c.store == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.store.Enrollment(ctx)
	if err != nil {
		return fmt.Errorf("read enrollment for recovery: %w", err)
	}
	if current.State != localstore.StateUnenrolling || !current.RevocationConfirmed {
		return nil
	}
	return c.completeConfirmed(ctx, current)
}

func (c *EnrollmentCoordinator) completeConfirmed(ctx context.Context, current localstore.Enrollment) error {
	c.runtime.StopEnrollmentNetwork()
	if err := c.runtime.WithPolicyAuthority(func() error { return nil }); err != nil {
		return err
	}
	err := c.runtime.RestoreStandalonePolicy(ctx, func(ctx context.Context) error {
		if err := c.runtime.RemoveEnrollmentCredentials(current); err != nil {
			return err
		}
		return c.store.CompleteUnenrollment(ctx, "endpoint")
	})
	if err != nil {
		return err
	}
	standalone := localstore.Enrollment{State: localstore.StateStandalone}
	c.runtime.ApplyEnrollmentNetwork(standalone)
	c.runtime.ApplyEnrollmentIdentity(standalone)
	return nil
}

func (c *EnrollmentCoordinator) prepareUnenrollment(ctx context.Context) (localstore.Enrollment, localstore.UnenrollmentCompletion, error) {
	current, err := c.store.Enrollment(ctx)
	if err != nil {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, err
	}
	if current.UnenrollmentProtocol == localstore.UnenrollmentProtocolLegacyMTLS {
		current, err = c.store.BeginUnenrollment(ctx)
		return current, localstore.UnenrollmentCompletion{}, err
	}
	if current.UnenrollmentProtocol != localstore.UnenrollmentProtocolCompletionV1 {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, fmt.Errorf("unsupported unenrollment protocol %q", current.UnenrollmentProtocol)
	}
	if current.State == localstore.StateUnenrolling {
		return c.preparedUnenrollment(ctx, current)
	}
	token, tokenHash, err := newUnenrollmentCompletionToken()
	if err != nil {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, err
	}
	current, err = c.store.PrepareUnenrollment(ctx, token, tokenHash)
	if err != nil {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, err
	}
	return c.preparedUnenrollment(ctx, current)
}

func (c *EnrollmentCoordinator) preparedUnenrollment(ctx context.Context, current localstore.Enrollment) (localstore.Enrollment, localstore.UnenrollmentCompletion, error) {
	completion, ok, err := c.store.UnenrollmentCompletion(ctx)
	if err != nil {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, fmt.Errorf("read prepared unenrollment completion: %w", err)
	}
	if !ok {
		return localstore.Enrollment{}, localstore.UnenrollmentCompletion{}, fmt.Errorf("prepared unenrollment completion does not exist")
	}
	return current, completion, nil
}

func newUnenrollmentCompletionToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate unenrollment completion token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(hash[:]), nil
}
