package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

func (b *tableBackend) ListAgents(ctx context.Context) ([]store.AgentIdentity, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return queryAgents(ctx, b.db)
}

func (b *tableBackend) ListAgentHealth(ctx context.Context, tenantID string) ([]agenthealth.AgentHealth, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return queryAgentHealth(ctx, b.db, tenantID, "")
}

func (b *tableBackend) GetAgentHealth(ctx context.Context, tenantID, agentID string) (agenthealth.AgentHealth, bool, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	rows, err := queryAgentHealth(ctx, b.db, tenantID, agentID)
	if err != nil {
		return agenthealth.AgentHealth{}, false, err
	}
	if len(rows) == 0 {
		return agenthealth.AgentHealth{}, false, nil
	}
	if len(rows) > 1 {
		return agenthealth.AgentHealth{}, false, nil
	}
	return rows[0], true, nil
}

func (b *tableBackend) ListAgentSessions(ctx context.Context, tenantID, agentID string) ([]store.AgentSession, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return queryAgentSessions(ctx, b.db, tenantID, agentID)
}

func queryAgents(ctx context.Context, db sqlExecutor) ([]store.AgentIdentity, error) {
	rows, err := db.QueryContext(ctx, `
SELECT data FROM agents
ORDER BY tenant_id ASC, agent_id ASC
`)
	if err != nil {
		return nil, fmt.Errorf("query postgres agents: %w", err)
	}
	defer rows.Close()
	var out []store.AgentIdentity
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres agent: %w", err)
		}
		var agent store.AgentIdentity
		if err := json.Unmarshal(raw, &agent); err != nil {
			return nil, fmt.Errorf("decode postgres agent: %w", err)
		}
		out = append(out, agent.Normalized())
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres agents: %w", err)
	}
	return out, nil
}

func queryAgentHealth(ctx context.Context, db sqlExecutor, tenantID, agentID string) ([]agenthealth.AgentHealth, error) {
	query := `
SELECT data FROM agent_health
WHERE ($1 = '' OR tenant_id = $1)
  AND ($2 = '' OR agent_id = $2)
ORDER BY tenant_id ASC, agent_id ASC
`
	rows, err := db.QueryContext(ctx, query, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("query postgres agent health: %w", err)
	}
	defer rows.Close()
	var out []agenthealth.AgentHealth
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres agent health: %w", err)
		}
		var health agenthealth.AgentHealth
		if err := json.Unmarshal(raw, &health); err != nil {
			return nil, fmt.Errorf("decode postgres agent health: %w", err)
		}
		out = append(out, health)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres agent health: %w", err)
	}
	return out, nil
}

func queryAgentSessions(ctx context.Context, db sqlExecutor, tenantID, agentID string) ([]store.AgentSession, error) {
	rows, err := db.QueryContext(ctx, `
SELECT data FROM agent_sessions
WHERE ($1 = '' OR tenant_id = $1)
  AND ($2 = '' OR agent_id = $2)
ORDER BY last_seen_at DESC, tenant_id ASC, agent_id ASC
`, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("query postgres agent sessions: %w", err)
	}
	defer rows.Close()
	out := []store.AgentSession{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan postgres agent session: %w", err)
		}
		var session store.AgentSession
		if err := json.Unmarshal(raw, &session); err != nil {
			return nil, fmt.Errorf("decode postgres agent session: %w", err)
		}
		out = append(out, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate postgres agent sessions: %w", err)
	}
	return out, nil
}

func projectAgents(ctx context.Context, db sqlExecutor, agentRows []json.RawMessage) error {
	for _, raw := range agentRows {
		var agent store.AgentIdentity
		if err := json.Unmarshal(raw, &agent); err != nil {
			return fmt.Errorf("decode agent projection: %w", err)
		}
		agent = agent.Normalized()
		if !agent.Valid() {
			continue
		}
		_, err := db.ExecContext(ctx, `
INSERT INTO agents (tenant_id, agent_id, host_id, version, data)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
  host_id = EXCLUDED.host_id,
  version = EXCLUDED.version,
  observed_at = now(),
  data = EXCLUDED.data
`, agent.TenantID, agent.AgentID, agent.HostID, agent.Version, []byte(raw))
		if err != nil {
			return fmt.Errorf("project agent: %w", err)
		}
	}
	return nil
}

func projectAgentHealth(ctx context.Context, db sqlExecutor, healthRows []json.RawMessage) error {
	for _, raw := range healthRows {
		var health agenthealth.AgentHealth
		if err := json.Unmarshal(raw, &health); err != nil {
			return fmt.Errorf("decode agent health projection: %w", err)
		}
		if health.AgentID == "" {
			continue
		}
		tenantID := health.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		observedAt := health.ObservedAt
		if observedAt.IsZero() {
			_, err := db.ExecContext(ctx, `
INSERT INTO agent_health (tenant_id, agent_id, host_id, scope_type, scope_selector, data)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
  host_id = EXCLUDED.host_id,
  scope_type = EXCLUDED.scope_type,
  scope_selector = EXCLUDED.scope_selector,
  observed_at = now(),
  data = EXCLUDED.data
`, tenantID, health.AgentID, health.HostID, health.Scope.Type, health.Scope.Selector, []byte(raw))
			if err != nil {
				return fmt.Errorf("project agent health: %w", err)
			}
			continue
		}
		_, err := db.ExecContext(ctx, `
INSERT INTO agent_health (tenant_id, agent_id, host_id, scope_type, scope_selector, observed_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
  host_id = EXCLUDED.host_id,
  scope_type = EXCLUDED.scope_type,
  scope_selector = EXCLUDED.scope_selector,
  observed_at = EXCLUDED.observed_at,
  data = EXCLUDED.data
`, tenantID, health.AgentID, health.HostID, health.Scope.Type, health.Scope.Selector, observedAt, []byte(raw))
		if err != nil {
			return fmt.Errorf("project agent health: %w", err)
		}
	}
	return nil
}

func projectAgentSessions(ctx context.Context, db sqlExecutor, sessions []store.AgentSession) error {
	for _, session := range sessions {
		if session.SessionID == "" || session.AgentID == "" {
			continue
		}
		tenantID := session.TenantID
		if tenantID == "" {
			tenantID = "default"
		}
		data, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("encode agent session projection: %w", err)
		}
		startedAt := session.StartedAt
		lastSeenAt := session.LastSeenAt
		var lastDataSeenAt any
		if !session.LastDataSeenAt.IsZero() {
			lastDataSeenAt = session.LastDataSeenAt
		}
		var lastControlSeenAt any
		if !session.LastControlSeenAt.IsZero() {
			lastControlSeenAt = session.LastControlSeenAt
		}
		if startedAt.IsZero() || lastSeenAt.IsZero() {
			_, err = db.ExecContext(ctx, `
INSERT INTO agent_sessions (tenant_id, session_id, agent_id, status, data_transport, control_transport, last_ack_cursor, last_data_seen_at, last_control_seen_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, session_id) DO UPDATE SET
  agent_id = EXCLUDED.agent_id,
  status = EXCLUDED.status,
  data_transport = EXCLUDED.data_transport,
  control_transport = EXCLUDED.control_transport,
  last_ack_cursor = EXCLUDED.last_ack_cursor,
  last_data_seen_at = EXCLUDED.last_data_seen_at,
  last_control_seen_at = EXCLUDED.last_control_seen_at,
  last_seen_at = now(),
  data = EXCLUDED.data
`, tenantID, session.SessionID, session.AgentID, session.Status, session.DataTransport, session.ControlTransport, session.LastAckCursor, lastDataSeenAt, lastControlSeenAt, data)
		} else if session.ClosedAt.IsZero() {
			_, err = db.ExecContext(ctx, `
INSERT INTO agent_sessions (tenant_id, session_id, agent_id, status, data_transport, control_transport, last_ack_cursor, started_at, last_seen_at, last_data_seen_at, last_control_seen_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, session_id) DO UPDATE SET
  agent_id = EXCLUDED.agent_id,
  status = EXCLUDED.status,
  data_transport = EXCLUDED.data_transport,
  control_transport = EXCLUDED.control_transport,
  last_ack_cursor = EXCLUDED.last_ack_cursor,
  last_seen_at = EXCLUDED.last_seen_at,
  last_data_seen_at = EXCLUDED.last_data_seen_at,
  last_control_seen_at = EXCLUDED.last_control_seen_at,
  closed_at = NULL,
  data = EXCLUDED.data
`, tenantID, session.SessionID, session.AgentID, session.Status, session.DataTransport, session.ControlTransport, session.LastAckCursor, startedAt, lastSeenAt, lastDataSeenAt, lastControlSeenAt, data)
		} else {
			_, err = db.ExecContext(ctx, `
INSERT INTO agent_sessions (tenant_id, session_id, agent_id, status, data_transport, control_transport, last_ack_cursor, started_at, last_seen_at, last_data_seen_at, last_control_seen_at, closed_at, data)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
ON CONFLICT (tenant_id, session_id) DO UPDATE SET
  agent_id = EXCLUDED.agent_id,
  status = EXCLUDED.status,
  data_transport = EXCLUDED.data_transport,
  control_transport = EXCLUDED.control_transport,
  last_ack_cursor = EXCLUDED.last_ack_cursor,
  last_seen_at = EXCLUDED.last_seen_at,
  last_data_seen_at = EXCLUDED.last_data_seen_at,
  last_control_seen_at = EXCLUDED.last_control_seen_at,
  closed_at = EXCLUDED.closed_at,
  data = EXCLUDED.data
`, tenantID, session.SessionID, session.AgentID, session.Status, session.DataTransport, session.ControlTransport, session.LastAckCursor, startedAt, lastSeenAt, lastDataSeenAt, lastControlSeenAt, session.ClosedAt, data)
		}
		if err != nil {
			return fmt.Errorf("project agent session: %w", err)
		}
	}
	return nil
}
