package identity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type GatewaySessionStore struct{ db dbBeginner }
type dbBeginner interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func NewGatewaySessionStore(db *sql.DB) GatewaySessionStore { return GatewaySessionStore{db: db} }

func (store GatewaySessionStore) IsDuplicate(ctx context.Context, tenantID, agentID, cursor string) (bool, error) {
	if _, err := tenant.NewID(tenantID); err != nil {
		return false, err
	}
	var exists bool
	err := store.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM agent_sessions WHERE tenant_id = $1 AND agent_id = $2 AND last_ack_cursor = $3)`, tenantID, agentID, cursor).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("query duplicate batch: %w", err)
	}
	return exists, nil
}

func (store GatewaySessionStore) RecordBatch(ctx context.Context, batch ports.BatchEnvelope) (ports.GatewaySession, error) {
	now, sessionID := time.Now().UTC(), stableSessionID(batch.TenantID, batch.AgentID)
	value := domainidentity.Session{TenantID: tenant.ID(batch.TenantID), ID: sessionID, AgentID: domainidentity.AgentID(batch.AgentID), StartedAt: now, LastSeenAt: now, LastDataSeenAt: now, LastAckCursor: batch.BatchID, DataTransport: batch.Transport, Status: "active"}
	document, err := json.Marshal(value)
	if err != nil {
		return ports.GatewaySession{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.GatewaySession{}, fmt.Errorf("begin session transaction: %w", err)
	}
	defer tx.Rollback()
	if err := upsertGatewayAgent(ctx, tx, batch, now); err != nil {
		return ports.GatewaySession{}, err
	}
	if err := upsertGatewaySession(ctx, tx, value, document); err != nil {
		return ports.GatewaySession{}, err
	}
	if err := tx.Commit(); err != nil {
		return ports.GatewaySession{}, fmt.Errorf("commit session transaction: %w", err)
	}
	return ports.GatewaySession{TenantID: batch.TenantID, AgentID: batch.AgentID, SessionID: sessionID, Cursor: batch.BatchID, LastSeenAt: now}, nil
}

func upsertGatewayAgent(ctx context.Context, tx *sql.Tx, batch ports.BatchEnvelope, now time.Time) error {
	document, _ := json.Marshal(map[string]string{"tenant_id": batch.TenantID, "agent_id": batch.AgentID, "host_id": batch.HostID})
	_, err := tx.ExecContext(ctx, `INSERT INTO agents (tenant_id, agent_id, host_id, observed_at, data) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,agent_id) DO UPDATE SET host_id=EXCLUDED.host_id, observed_at=EXCLUDED.observed_at, data=EXCLUDED.data`, batch.TenantID, batch.AgentID, batch.HostID, now, document)
	if err != nil {
		return fmt.Errorf("upsert gateway agent: %w", err)
	}
	return nil
}
func upsertGatewaySession(ctx context.Context, tx *sql.Tx, value domainidentity.Session, document []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO agent_sessions (tenant_id,session_id,agent_id,status,data_transport,last_ack_cursor,started_at,last_seen_at,last_data_seen_at,data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (tenant_id,session_id) DO UPDATE SET agent_id=EXCLUDED.agent_id,status=EXCLUDED.status,data_transport=EXCLUDED.data_transport,last_ack_cursor=EXCLUDED.last_ack_cursor,last_seen_at=EXCLUDED.last_seen_at,last_data_seen_at=EXCLUDED.last_data_seen_at,data=EXCLUDED.data`, value.TenantID.String(), value.ID, string(value.AgentID), value.Status, value.DataTransport, value.LastAckCursor, value.StartedAt, value.LastSeenAt, value.LastDataSeenAt, document)
	if err != nil {
		return fmt.Errorf("upsert gateway session: %w", err)
	}
	return nil
}
func stableSessionID(tenantID, agentID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + agentID))
	return hex.EncodeToString(sum[:16])
}
