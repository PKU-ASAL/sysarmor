package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
)

type enrollmentCoordinator struct {
	*agentcontrol.EnrollmentCoordinator
	completeUnenrollment func(context.Context, string) error
}

type enrollmentStore struct {
	*localstore.Store
	complete func(context.Context, string) error
}

func (s *enrollmentStore) CompleteUnenrollment(ctx context.Context, kind string) error {
	return s.complete(ctx, kind)
}

type enrollmentRuntime struct {
	runner  *AgentRuntime
	runtime sensorruntime.Runtime
}

type enrollmentPreparationState struct {
	paths          credentialPaths
	created        bool
	pendingKeyPath string
}

func newEnrollmentCoordinator(lifecycleCtx context.Context, runner *AgentRuntime, runtime sensorruntime.Runtime) *enrollmentCoordinator {
	coordinator := &enrollmentCoordinator{}
	if runner.localStore == nil {
		coordinator.EnrollmentCoordinator = agentcontrol.NewEnrollmentCoordinator(lifecycleCtx, nil, newEnrollmentRuntime(runner, runtime))
		return coordinator
	}
	store := &enrollmentStore{Store: runner.localStore}
	store.complete = func(ctx context.Context, kind string) error {
		if coordinator.completeUnenrollment != nil {
			return coordinator.completeUnenrollment(ctx, kind)
		}
		return runner.localStore.CompleteUnenrollment(ctx, kind)
	}
	coordinator.EnrollmentCoordinator = agentcontrol.NewEnrollmentCoordinator(lifecycleCtx, store, newEnrollmentRuntime(runner, runtime))
	return coordinator
}

func newEnrollmentRuntime(runner *AgentRuntime, runtime sensorruntime.Runtime) *enrollmentRuntime {
	return &enrollmentRuntime{runner: runner, runtime: runtime}
}

func (r *enrollmentRuntime) EnrollmentIdentity() agentcontrol.EnrollmentIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.EnrollmentIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *enrollmentRuntime) PrepareEnrollment(ctx context.Context, managerURL, token string) (agentcontrol.EnrollmentPreparation, error) {
	certificate, keyPEM, pendingKeyPath, err := requestEnrollmentCertificate(ctx, managerURL, token, r.runner.Config.Local.StatePath)
	if err != nil {
		return agentcontrol.EnrollmentPreparation{}, err
	}
	paths, created, err := writeEnrollmentCredentials(r.runner.Config.Local.StatePath, certificate, keyPEM)
	if err != nil {
		return agentcontrol.EnrollmentPreparation{}, fmt.Errorf("write credentials: %v", err)
	}
	enrollment := localstore.Enrollment{
		State: localstore.StateEnrolling, TenantID: certificate.TenantID, AgentID: certificate.AgentID,
		EnrollmentID: certificate.EnrollmentID, CertificateSerial: certificate.SerialNumber, ManagerURL: managerURL,
		GatewayAddress: certificate.GatewayAddress, TLSCAPath: paths.CA, TLSCertPath: paths.Certificate,
		TLSKeyPath: paths.Key, TLSServerName: certificate.GatewayServerName,
	}
	state := enrollmentPreparationState{paths: paths, created: created, pendingKeyPath: pendingKeyPath}
	return agentcontrol.EnrollmentPreparation{Enrollment: enrollment, Handle: state}, nil
}

func (r *enrollmentRuntime) RollbackEnrollment(preparation agentcontrol.EnrollmentPreparation, cause error) error {
	state, ok := preparation.Handle.(enrollmentPreparationState)
	if !ok {
		return cause
	}
	return rollbackEnrollmentFailure(state.paths, state.created, cause)
}

func (r *enrollmentRuntime) FinalizeEnrollment(preparation agentcontrol.EnrollmentPreparation) {
	state, ok := preparation.Handle.(enrollmentPreparationState)
	if !ok || state.pendingKeyPath == "" {
		return
	}
	if err := os.Remove(state.pendingKeyPath); err != nil && !os.IsNotExist(err) && r.runner.Out != nil {
		fmt.Fprintf(r.runner.Out, "remove pending enrollment key: %v\n", err)
	}
}

func (r *enrollmentRuntime) StopEnrollmentNetwork() {
	if r.runner.network != nil {
		r.runner.network.Stop()
	}
}

func (r *enrollmentRuntime) ReconcileEnrollment(enrollment localstore.Enrollment) error {
	return r.runner.reconcileManagementContext(enrollment)
}

func (r *enrollmentRuntime) WithPolicyAuthority(run func() error) error {
	r.runner.policyAuthorityMu.Lock()
	defer r.runner.policyAuthorityMu.Unlock()
	return run()
}

func (r *enrollmentRuntime) RevokeEnrollment(ctx context.Context, enrollment localstore.Enrollment, tokenHash string) (string, time.Time, error) {
	if r.runner.revokeEnrollment != nil {
		return r.runner.revokeEnrollment(ctx, enrollment, tokenHash)
	}
	return revokeEnrollmentOnline(ctx, enrollment, tokenHash)
}

func (r *enrollmentRuntime) RestoreStandalonePolicy(ctx context.Context, activate func(context.Context) error) error {
	return newEndpointPolicyApplication(r.runner, r.runtime, nil).RestoreStandalone(ctx, activate)
}

func (r *enrollmentRuntime) RemoveEnrollmentCredentials(enrollment localstore.Enrollment) error {
	paths := credentialPaths{CA: enrollment.TLSCAPath, Certificate: enrollment.TLSCertPath, Key: enrollment.TLSKeyPath}
	if failures := removeCredentials(paths); len(failures) > 0 {
		return fmt.Errorf("remove enrollment credentials: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (r *enrollmentRuntime) ReportUnenrollmentCompletion(ctx context.Context) (bool, error) {
	if r.runner.reportUnenrollment != nil {
		return r.runner.reportUnenrollment(ctx)
	}
	if r.runner.completionReporter == nil {
		return false, fmt.Errorf("unenrollment completion reporter is unavailable")
	}
	return r.runner.completionReporter.ReportOnce(ctx)
}
