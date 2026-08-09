package store

import (
	"fmt"
	"sort"
	"strings"
	"time"

	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type AgentIdentity struct {
	AgentID      string `json:"agent_id"`
	HostID       string `json:"host_id,omitempty"`
	Version      string `json:"version,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	AuthType     string `json:"auth_type,omitempty"`
	CertIdentity string `json:"cert_identity,omitempty"`
}

func AgentIdentityFromDataBatch(batch *dataplanev1.DataBatch) AgentIdentity {
	header := batch.GetHeader()
	agent := AgentIdentity{
		AgentID:  header.GetAgentId(),
		HostID:   header.GetHostId(),
		TenantID: header.GetTenantId(),
	}
	if header.GetLabels() != nil {
		agent.Version = header.GetLabels()["agent_version"]
	}
	return agent.Normalized()
}

func (a AgentIdentity) Normalized() AgentIdentity {
	a.AgentID = strings.TrimSpace(a.AgentID)
	a.HostID = strings.TrimSpace(a.HostID)
	a.Version = strings.TrimSpace(a.Version)
	a.TenantID = strings.TrimSpace(a.TenantID)
	a.AuthType = strings.TrimSpace(a.AuthType)
	a.CertIdentity = strings.TrimSpace(a.CertIdentity)
	if a.TenantID == "" {
		a.TenantID = "default"
	}
	return a
}

func (a AgentIdentity) Valid() bool {
	return strings.TrimSpace(a.AgentID) != ""
}

func (s *Store) AddAgent(agent AgentIdentity) {
	agent = agent.Normalized()
	if !agent.Valid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.Agents {
		if existing.TenantID == agent.TenantID && existing.AgentID == agent.AgentID {
			if agent.HostID == "" {
				agent.HostID = existing.HostID
			}
			if agent.Version == "" {
				agent.Version = existing.Version
			}
			if agent.AuthType == "" {
				agent.AuthType = existing.AuthType
			}
			if agent.CertIdentity == "" {
				agent.CertIdentity = existing.CertIdentity
			}
			s.Agents[i] = agent
			return
		}
	}
	s.Agents = append(s.Agents, agent)
}

func (s *Store) BindAgentIdentity(agent AgentIdentity) error {
	agent = agent.Normalized()
	if !agent.Valid() {
		return fmt.Errorf("agent_id is required")
	}
	if agent.AuthType == "" || agent.CertIdentity == "" {
		return fmt.Errorf("auth_type and cert_identity are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.Agents {
		if existing.TenantID != agent.TenantID || existing.AgentID != agent.AgentID {
			continue
		}
		if existing.CertIdentity != "" && existing.CertIdentity != agent.CertIdentity {
			return fmt.Errorf("agent identity binding mismatch: registered=%s presented=%s", existing.CertIdentity, agent.CertIdentity)
		}
		if existing.AuthType != "" && existing.AuthType != agent.AuthType {
			return fmt.Errorf("agent auth binding mismatch: registered=%s presented=%s", existing.AuthType, agent.AuthType)
		}
		if agent.HostID == "" {
			agent.HostID = existing.HostID
		}
		if agent.Version == "" {
			agent.Version = existing.Version
		}
		s.Agents[i] = agent
		return nil
	}
	s.Agents = append(s.Agents, agent)
	return nil
}

func (s *Store) UpsertAgentHealth(health agenthealth.AgentHealth) {
	if health.AgentID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Health == nil {
		s.Health = map[string]agenthealth.AgentHealth{}
	}
	s.Health[agentHealthKey(health.TenantID, health.AgentID)] = health
}

func (s *Store) RecordDataBatchAppend(agent AgentIdentity, batchID, transport string, observedAt time.Time) AgentSession {
	agent = agent.Normalized()
	if !agent.Valid() {
		return AgentSession{}
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	sessionID := agentSessionID(agent.TenantID, agent.AgentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.AgentSessions {
		if existing.SessionID == sessionID {
			existing.LastSeenAt = observedAt
			existing.LastDataSeenAt = observedAt
			if batchID != "" {
				existing.LastAckCursor = batchID
			}
			if transport != "" {
				existing.DataTransport = transport
			}
			existing.Status = "active"
			existing.ClosedAt = time.Time{}
			s.AgentSessions[i] = existing
			return existing
		}
	}
	session := AgentSession{
		SessionID:      sessionID,
		TenantID:       agent.TenantID,
		AgentID:        agent.AgentID,
		StartedAt:      observedAt,
		LastSeenAt:     observedAt,
		LastDataSeenAt: observedAt,
		LastAckCursor:  batchID,
		DataTransport:  transport,
		Status:         "active",
	}
	s.AgentSessions = append(s.AgentSessions, session)
	return session
}

func (s *Store) RecordControlSessionOpen(tenantID, agentID, transport string, observedAt time.Time) AgentSession {
	return s.updateAgentSession(tenantID, agentID, transport, "", "open", observedAt, false)
}

func (s *Store) RecordAgentSessionSeen(tenantID, agentID string, observedAt time.Time) AgentSession {
	return s.updateAgentSession(tenantID, agentID, "", "", "", observedAt, false)
}

func (s *Store) CloseAgentSession(tenantID, agentID string, observedAt time.Time) AgentSession {
	return s.updateAgentSession(tenantID, agentID, "", "", "closed", observedAt, true)
}

func (s *Store) updateAgentSession(tenantID, agentID, transport, cursor, status string, observedAt time.Time, closeSession bool) AgentSession {
	tenantID = strings.TrimSpace(tenantID)
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return AgentSession{}
	}
	if tenantID == "" {
		tenantID = "default"
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	sessionID := agentSessionID(tenantID, agentID)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, session := range s.AgentSessions {
		if session.SessionID != sessionID {
			continue
		}
		session.LastSeenAt = observedAt
		if transport != "" {
			session.ControlTransport = transport
			session.LastControlSeenAt = observedAt
		}
		if cursor != "" {
			session.LastAckCursor = cursor
		}
		if status != "" {
			session.Status = status
		}
		if closeSession {
			session.ClosedAt = observedAt
		} else if status == "open" {
			session.ClosedAt = time.Time{}
		}
		s.AgentSessions[i] = session
		return session
	}
	session := AgentSession{
		SessionID:        sessionID,
		TenantID:         tenantID,
		AgentID:          agentID,
		StartedAt:        observedAt,
		LastSeenAt:       observedAt,
		LastAckCursor:    cursor,
		ControlTransport: transport,
		Status:           status,
	}
	if transport != "" {
		session.LastControlSeenAt = observedAt
	}
	if session.Status == "" {
		session.Status = "active"
	}
	if closeSession {
		session.ClosedAt = observedAt
	}
	s.AgentSessions = append(s.AgentSessions, session)
	return session
}

func (s *Store) ListAgents() []AgentIdentity {
	if backend, ctx := s.backendCtx(); backend != nil {
		if agents, err := backend.ListAgents(ctx); err == nil {
			return agents
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentIdentity, len(s.Agents))
	copy(out, s.Agents)
	return out
}

func (s *Store) ListAgentSessions(tenantID, agentID string) []AgentSession {
	if backend, ctx := s.backendCtx(); backend != nil {
		if sessions, err := backend.ListAgentSessions(ctx, tenantID, agentID); err == nil {
			return sessions
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentSession, 0, len(s.AgentSessions))
	for _, session := range s.AgentSessions {
		if tenantID != "" && session.TenantID != tenantID {
			continue
		}
		if agentID != "" && session.AgentID != agentID {
			continue
		}
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func (s *Store) ListAgentHealth() []agenthealth.AgentHealth {
	if backend, ctx := s.backendCtx(); backend != nil {
		if health, err := backend.ListAgentHealth(ctx, ""); err == nil {
			return health
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]agenthealth.AgentHealth, 0, len(s.Health))
	for _, health := range s.Health {
		out = append(out, health)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func (s *Store) GetAgentHealth(tenantID, agentID string) (agenthealth.AgentHealth, bool) {
	if backend, ctx := s.backendCtx(); backend != nil {
		if health, ok, err := backend.GetAgentHealth(ctx, tenantID, agentID); err == nil {
			return health, ok
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if agentID == "" {
		return agenthealth.AgentHealth{}, false
	}
	if tenantID != "" {
		health, ok := s.Health[agentHealthKey(tenantID, agentID)]
		return health, ok
	}
	var found agenthealth.AgentHealth
	var ok bool
	for _, health := range s.Health {
		if health.AgentID == agentID {
			if ok && found.TenantID != health.TenantID {
				return agenthealth.AgentHealth{}, false
			}
			found = health
			ok = true
		}
	}
	return found, ok
}

func agentHealthKey(tenantID, agentID string) string {
	return tenantID + "/" + agentID
}

func agentSessionID(tenantID, agentID string) string {
	return stableKey(tenantID, agentID)
}
