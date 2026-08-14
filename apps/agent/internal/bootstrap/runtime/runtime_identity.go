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

func (r *managementRuntime) bindControlAckIdentity(ack *controlplanev1.ControlAck) *controlplanev1.ControlAck {
	return bindControlAckToSession(ack, r.currentIdentity())
}

func (r *managementRuntime) setRuntimeIdentity(identity runtimeIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identity = identity
	if r.standaloneIdentity.AgentID == "" {
		r.standaloneIdentity = identity
	}
	normalizer := r.normalizer
	if normalizer != nil {
		normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
	}
}

func (r *managementRuntime) currentIdentity() runtimeIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.identity.AgentID != "" {
		return r.identity
	}
	return runtimeIdentity{AgentID: r.config.Agent.ID, HostID: r.config.Agent.HostID, TenantID: r.config.Agent.TenantID}
}

func (r *managementRuntime) standaloneRuntimeIdentity() runtimeIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.standaloneIdentity.AgentID != "" {
		return r.standaloneIdentity
	}
	return runtimeIdentity{AgentID: r.config.Agent.ID, HostID: r.config.Agent.HostID, TenantID: r.config.Agent.TenantID}
}

func (r *managementRuntime) setNormalizer(normalizer *eventadapter.EventNormalizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.normalizer = normalizer
	identity := r.identity
	if identity.AgentID == "" {
		identity = runtimeIdentity{AgentID: r.config.Agent.ID, HostID: r.config.Agent.HostID, TenantID: r.config.Agent.TenantID}
	}
	normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
}
