package daemon

import (
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/management"
)

func (r *AgentRuntime) reconcileManagementContext(enrollment localstore.Enrollment) error {
	mode, err := management.Resolve(enrollment.State)
	if err != nil {
		return err
	}
	identity, err := r.identityForManagementContext(enrollment, mode)
	if err != nil {
		return err
	}
	r.applyProjectedIdentity(identity)
	if r.network != nil {
		if !r.network.PromoteEnrollment(enrollment, mode) {
			r.network.ApplyEnrollment(enrollment, mode)
		}
	}
	return nil
}

func (r *AgentRuntime) identityForManagementContext(enrollment localstore.Enrollment, mode management.Context) (runtimeIdentity, error) {
	if mode.IdentitySource == management.IdentityStandalone {
		return r.standaloneRuntimeIdentity(), nil
	}
	if strings.TrimSpace(enrollment.AgentID) == "" || strings.TrimSpace(enrollment.TenantID) == "" {
		return runtimeIdentity{}, fmt.Errorf("enrollment identity is incomplete")
	}
	standalone := r.standaloneRuntimeIdentity()
	return runtimeIdentity{AgentID: enrollment.AgentID, HostID: standalone.HostID, TenantID: enrollment.TenantID}, nil
}

func (r *AgentRuntime) applyProjectedIdentity(identity runtimeIdentity) {
	if identity != r.currentIdentity() && r.telemetryBatcher != nil {
		r.telemetryBatcher.Flush("identity")
	}
	r.setRuntimeIdentity(identity)
}
