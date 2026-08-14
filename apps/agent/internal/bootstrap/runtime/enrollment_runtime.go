package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	adapterenrollment "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/enrollment"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	appenrollment "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/management"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type enrollmentCoordinator struct {
	*appenrollment.Service
	completeUnenrollment func(context.Context, string) error
}

type enrollmentRuntime struct {
	runner  *Runtime
	runtime sensorruntime.Runtime
}

type enrollmentPreparationState struct {
	enrollment     ports.Enrollment
	paths          adapterenrollment.CredentialPaths
	created        bool
	pendingKeyPath string
}

func (s enrollmentPreparationState) PreparedEnrollment() ports.Enrollment { return s.enrollment }

func newEnrollmentCoordinator(lifecycleCtx context.Context, runner *Runtime, runtime sensorruntime.Runtime) *enrollmentCoordinator {
	coordinator := &enrollmentCoordinator{}
	if runner.localStore == nil {
		coordinator.Service = appenrollment.NewService(lifecycleCtx, nil, newEnrollmentRuntime(runner, runtime))
		return coordinator
	}
	complete := func(ctx context.Context, kind string) error {
		if coordinator.completeUnenrollment != nil {
			return coordinator.completeUnenrollment(ctx, kind)
		}
		return runner.localStore.CompleteUnenrollment(ctx, kind)
	}
	store := adapterenrollment.NewStore(runner.localStore, complete)
	coordinator.Service = appenrollment.NewService(lifecycleCtx, store, newEnrollmentRuntime(runner, runtime))
	return coordinator
}

func newEnrollmentRuntime(runner *Runtime, runtime sensorruntime.Runtime) *enrollmentRuntime {
	return &enrollmentRuntime{runner: runner, runtime: runtime}
}

func (r *enrollmentRuntime) Identity() ports.EnrollmentIdentity {
	identity := r.runner.currentIdentity()
	return ports.EnrollmentIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (r *enrollmentRuntime) PrepareEnrollment(ctx context.Context, managerURL, token string) (ports.EnrollmentPreparation, error) {
	certificate, keyPEM, pendingKeyPath, err := adapterenrollment.RequestCertificate(ctx, managerURL, token, r.runner.Config.Local.StatePath)
	if err != nil {
		return nil, err
	}
	paths, created, err := adapterenrollment.WriteCredentials(r.runner.Config.Local.StatePath, certificate, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("write credentials: %v", err)
	}
	enrollment := ports.Enrollment{
		State: management.StateEnrolling, TenantID: certificate.TenantID, AgentID: certificate.AgentID,
		EnrollmentID: certificate.EnrollmentID, CertificateSerial: certificate.SerialNumber, ManagerURL: managerURL,
		GatewayAddress: certificate.GatewayAddress, TLSCAPath: paths.CA, TLSCertPath: paths.Certificate,
		TLSKeyPath: paths.Key, TLSServerName: certificate.GatewayServerName,
	}
	return enrollmentPreparationState{enrollment: enrollment, paths: paths, created: created, pendingKeyPath: pendingKeyPath}, nil
}

func (r *enrollmentRuntime) RollbackEnrollment(preparation ports.EnrollmentPreparation, cause error) error {
	state, ok := preparation.(enrollmentPreparationState)
	if !ok {
		return cause
	}
	return adapterenrollment.RollbackFailure(state.paths, state.created, cause)
}

func (r *enrollmentRuntime) FinalizeEnrollment(preparation ports.EnrollmentPreparation) error {
	state, ok := preparation.(enrollmentPreparationState)
	if !ok || state.pendingKeyPath == "" {
		return nil
	}
	return adapterenrollment.RemovePendingKey(state.pendingKeyPath)
}

func (r *enrollmentRuntime) StopEnrollmentNetwork() {
	if r.runner.network != nil {
		r.runner.network.Stop()
	}
}

func (r *enrollmentRuntime) ReconcileEnrollment(enrollment ports.Enrollment) error {
	return r.runner.reconcileManagementContext(localEnrollment(enrollment))
}

func (r *enrollmentRuntime) WithPolicyAuthority(run func() error) error {
	r.runner.policyAuthorityMu.Lock()
	defer r.runner.policyAuthorityMu.Unlock()
	return run()
}

func (r *enrollmentRuntime) RevokeEnrollment(ctx context.Context, enrollment ports.Enrollment, tokenHash string) (string, time.Time, error) {
	if r.runner.revokeEnrollment != nil {
		return r.runner.revokeEnrollment(ctx, localEnrollment(enrollment), tokenHash)
	}
	return adapterenrollment.Revoke(ctx, localEnrollment(enrollment), tokenHash)
}

func (r *enrollmentRuntime) RestoreStandalonePolicy(ctx context.Context, activate func(context.Context) error) error {
	return newEndpointPolicyApplication(r.runner, r.runtime, nil).RestoreStandalone(ctx, activate)
}

func (r *enrollmentRuntime) RemoveEnrollmentCredentials(enrollment ports.Enrollment) error {
	paths := adapterenrollment.CredentialPaths{CA: enrollment.TLSCAPath, Certificate: enrollment.TLSCertPath, Key: enrollment.TLSKeyPath}
	if failures := adapterenrollment.RemoveCredentials(paths); len(failures) > 0 {
		return fmt.Errorf("remove enrollment credentials: %s", strings.Join(failures, "; "))
	}
	return nil
}

func localEnrollment(value ports.Enrollment) sqlite.Enrollment {
	return sqlite.Enrollment{
		State: value.State, TenantID: value.TenantID, AgentID: value.AgentID,
		EnrollmentID: value.EnrollmentID, CertificateSerial: value.CertificateSerial,
		ManagerURL:     value.ManagerURL,
		GatewayAddress: value.GatewayAddress, TLSCAPath: value.TLSCAPath,
		TLSCertPath: value.TLSCertPath, TLSKeyPath: value.TLSKeyPath,
		TLSServerName: value.TLSServerName, UploadHistory: value.UploadHistory,
		ManagedFromSequence: value.ManagedFromSequence, RevocationConfirmed: value.RevocationConfirmed,
		RevokedAt: value.RevokedAt, RevocationReceipt: value.RevocationReceipt,
	}
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
