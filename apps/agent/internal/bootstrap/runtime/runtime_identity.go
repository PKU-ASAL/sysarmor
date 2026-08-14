package runtime

import (
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func bindControlAckToSession(ack *controlplanev1.ControlAck, identity runtimeIdentity) *controlplanev1.ControlAck {
	if ack == nil {
		return nil
	}
	ack.AgentId = identity.AgentID
	ack.TenantId = identity.TenantID
	return ack
}

func bindHealthToSession(health agenthealth.AgentHealth, identity runtimeIdentity) agenthealth.AgentHealth {
	health.AgentID = identity.AgentID
	health.TenantID = identity.TenantID
	if identity.HostID != "" {
		health.HostID = identity.HostID
	}
	return health
}

type runtimeIdentity struct {
	AgentID  string
	HostID   string
	TenantID string
}

func (r *Coordinator) bindControlAckIdentity(ack *controlplanev1.ControlAck) *controlplanev1.ControlAck {
	return bindControlAckToSession(ack, r.currentIdentity())
}

func (r *Coordinator) setRuntimeIdentity(identity runtimeIdentity) {
	r.managementRuntime.mu.Lock()
	r.identity = identity
	if r.standaloneIdentity.AgentID == "" {
		r.standaloneIdentity = identity
	}
	r.managementRuntime.mu.Unlock()
	r.telemetryRuntime.mu.RLock()
	normalizer := r.normalizer
	r.telemetryRuntime.mu.RUnlock()
	if normalizer != nil {
		normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
	}
}

func (r *Coordinator) currentIdentity() runtimeIdentity {
	r.managementRuntime.mu.RLock()
	defer r.managementRuntime.mu.RUnlock()
	if r.identity.AgentID != "" {
		return r.identity
	}
	return runtimeIdentity{AgentID: r.Config.Agent.ID, HostID: r.Config.Agent.HostID, TenantID: r.Config.Agent.TenantID}
}

func (r *Coordinator) standaloneRuntimeIdentity() runtimeIdentity {
	r.managementRuntime.mu.RLock()
	defer r.managementRuntime.mu.RUnlock()
	if r.standaloneIdentity.AgentID != "" {
		return r.standaloneIdentity
	}
	return runtimeIdentity{AgentID: r.Config.Agent.ID, HostID: r.Config.Agent.HostID, TenantID: r.Config.Agent.TenantID}
}

func (r *Coordinator) setNormalizer(normalizer *eventadapter.EventNormalizer) {
	identity := r.currentIdentity()
	r.telemetryRuntime.mu.Lock()
	r.normalizer = normalizer
	r.telemetryRuntime.mu.Unlock()
	normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
}
