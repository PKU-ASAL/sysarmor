package daemon

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

func (r *AgentRuntime) bindControlAckIdentity(ack *controlplanev1.ControlAck) *controlplanev1.ControlAck {
	return bindControlAckToSession(ack, r.currentIdentity())
}

func (r *AgentRuntime) setRuntimeIdentity(identity runtimeIdentity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identity = identity
	if r.standaloneIdentity.AgentID == "" {
		r.standaloneIdentity = identity
	}
	if r.normalizer != nil {
		r.normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
	}
}

func (r *AgentRuntime) currentIdentity() runtimeIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.identity.AgentID != "" {
		return r.identity
	}
	return runtimeIdentity{AgentID: r.Config.Agent.ID, HostID: r.Config.Agent.HostID, TenantID: r.Config.Agent.TenantID}
}

func (r *AgentRuntime) standaloneRuntimeIdentity() runtimeIdentity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.standaloneIdentity.AgentID != "" {
		return r.standaloneIdentity
	}
	return runtimeIdentity{AgentID: r.Config.Agent.ID, HostID: r.Config.Agent.HostID, TenantID: r.Config.Agent.TenantID}
}

func (r *AgentRuntime) setNormalizer(normalizer *eventadapter.EventNormalizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.normalizer = normalizer
	identity := r.identity
	if identity.AgentID == "" {
		identity = runtimeIdentity{AgentID: r.Config.Agent.ID, HostID: r.Config.Agent.HostID, TenantID: r.Config.Agent.TenantID}
	}
	normalizer.SetIdentity(identity.AgentID, identity.HostID, identity.TenantID)
}
