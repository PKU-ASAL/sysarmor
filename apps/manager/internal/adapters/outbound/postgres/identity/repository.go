package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type Repositories struct{ db *sql.DB }

func NewRepositories(db *sql.DB) *Repositories                 { return &Repositories{db: db} }
func (repo *Repositories) Agents() ports.AgentRepository       { return agentRepository{db: repo.db} }
func (repo *Repositories) Health() ports.AgentHealthRepository { return healthRepository{db: repo.db} }
func (repo *Repositories) Sessions() ports.AgentSessionRepository {
	return sessionRepository{db: repo.db}
}
func (repo *Repositories) Snapshots() ports.IdentitySnapshotRepository {
	return snapshotRepository{db: repo.db}
}

type agentRepository struct{ db *sql.DB }

func (repo agentRepository) List(ctx context.Context, tenantID tenant.ID, filter domainidentity.AgentFilter) ([]domainidentity.Agent, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT agent_id, COALESCE(host_id, ''), COALESCE(version, ''), data FROM agents WHERE tenant_id = $1 ORDER BY agent_id ASC`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("query agents: %w", err)
	}
	defer rows.Close()
	result := []domainidentity.Agent{}
	for rows.Next() {
		var id, host, version string
		var document []byte
		if err := rows.Scan(&id, &host, &version, &document); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		value, err := decodeAgent(tenantID, id, host, version, document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agents: %w", err)
	}
	return filterAgents(result, filter, nil), nil
}

type healthRepository struct{ db *sql.DB }

func (repo healthRepository) Get(ctx context.Context, tenantID tenant.ID, agentID domainidentity.AgentID) (domainidentity.Health, error) {
	if err := requireTenant(tenantID); err != nil {
		return domainidentity.Health{}, err
	}
	row := repo.db.QueryRowContext(ctx, `SELECT COALESCE(host_id, ''), COALESCE(scope_type, ''), COALESCE(scope_selector, ''), observed_at, data FROM agent_health WHERE tenant_id = $1 AND agent_id = $2`, tenantID.String(), string(agentID))
	var host, scopeType, scopeSelector string
	var observed sql.NullTime
	var document []byte
	if err := row.Scan(&host, &scopeType, &scopeSelector, &observed, &document); err != nil {
		if err == sql.ErrNoRows {
			return domainidentity.Health{}, failure.New(failure.NotFound, "agent health not found")
		}
		return domainidentity.Health{}, fmt.Errorf("read agent health: %w", err)
	}
	return decodeHealth(tenantID, agentID, host, scopeType, scopeSelector, observedTime(observed), document)
}

func (repo healthRepository) List(ctx context.Context, tenantID tenant.ID, filter domainidentity.HealthFilter) ([]domainidentity.Health, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT agent_id, COALESCE(host_id, ''), COALESCE(scope_type, ''), COALESCE(scope_selector, ''), observed_at, data FROM agent_health WHERE tenant_id = $1 AND ($2 = '' OR agent_id = $2) ORDER BY agent_id ASC`, tenantID.String(), filter.AgentID)
	if err != nil {
		return nil, fmt.Errorf("query agent health: %w", err)
	}
	defer rows.Close()
	result := []domainidentity.Health{}
	for rows.Next() {
		var id, host, scopeType, scopeSelector string
		var observed sql.NullTime
		var document []byte
		if err := rows.Scan(&id, &host, &scopeType, &scopeSelector, &observed, &document); err != nil {
			return nil, fmt.Errorf("scan agent health: %w", err)
		}
		value, err := decodeHealth(tenantID, domainidentity.AgentID(id), host, scopeType, scopeSelector, observedTime(observed), document)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent health: %w", err)
	}
	return result, nil
}

type sessionRepository struct{ db *sql.DB }

func (repo sessionRepository) List(ctx context.Context, tenantID tenant.ID, filter domainidentity.SessionFilter) ([]domainidentity.Session, error) {
	if err := requireTenant(tenantID); err != nil {
		return nil, err
	}
	rows, err := repo.db.QueryContext(ctx, `SELECT session_id, agent_id, started_at, last_seen_at, last_data_seen_at, last_control_seen_at, closed_at, last_ack_cursor, data_transport, control_transport, status FROM agent_sessions WHERE tenant_id = $1 AND ($2 = '' OR agent_id = $2) ORDER BY last_seen_at DESC, session_id ASC`, tenantID.String(), filter.AgentID)
	if err != nil {
		return nil, fmt.Errorf("query agent sessions: %w", err)
	}
	defer rows.Close()
	result := []domainidentity.Session{}
	for rows.Next() {
		var value domainidentity.Session
		var tenantRaw string
		if err := rows.Scan(&value.ID, &value.AgentID, &value.StartedAt, &value.LastSeenAt, &value.LastDataSeenAt, &value.LastControlSeenAt, &value.ClosedAt, &value.LastAckCursor, &value.DataTransport, &value.ControlTransport, &value.Status); err != nil {
			return nil, fmt.Errorf("scan agent session: %w", err)
		}
		_ = tenantRaw
		value.TenantID = tenantID
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent sessions: %w", err)
	}
	return result, nil
}

type snapshotRepository struct{ db *sql.DB }

func (repo snapshotRepository) Metrics(ctx context.Context, tenantID tenant.ID) (domainidentity.Metrics, error) {
	return readSnapshot(ctx, repo.db, "tenant_metrics", tenantID, decodeMetrics)
}
func (repo snapshotRepository) Rarity(ctx context.Context, tenantID tenant.ID) (domainidentity.RarityBaseline, error) {
	return readSnapshot(ctx, repo.db, "rarity_baseline", tenantID, decodeRarity)
}

func requireTenant(id tenant.ID) error {
	if id.IsZero() {
		return failure.New(failure.InvalidArgument, "tenant is required")
	}
	return nil
}

func filterAgents(values []domainidentity.Agent, _ domainidentity.AgentFilter, _ map[domainidentity.AgentID]domainidentity.Health) []domainidentity.Agent {
	return values
}

func observedTime(value sql.NullTime) time.Time {
	if value.Valid {
		return value.Time
	}
	return time.Time{}
}

func readSnapshot[T any](ctx context.Context, db *sql.DB, table string, tenantID tenant.ID, decode func(tenant.ID, []byte) (T, error)) (T, error) {
	var zero T
	if err := requireTenant(tenantID); err != nil {
		return zero, err
	}
	var document []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM "+table+" WHERE tenant_id = $1", tenantID.String()).Scan(&document); err != nil {
		if err == sql.ErrNoRows {
			return zero, nil
		}
		return zero, fmt.Errorf("read %s: %w", table, err)
	}
	return decode(tenantID, document)
}

func decodeMetrics(_ tenant.ID, document []byte) (domainidentity.Metrics, error) {
	var value domainidentity.Metrics
	err := json.Unmarshal(document, &value)
	return value, err
}
func decodeRarity(_ tenant.ID, document []byte) (domainidentity.RarityBaseline, error) {
	var value domainidentity.RarityBaseline
	err := json.Unmarshal(document, &value)
	return value, err
}
