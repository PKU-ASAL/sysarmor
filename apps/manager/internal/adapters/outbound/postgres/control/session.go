package control

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

type SessionRepository struct {
	db *sql.DB
}

type messageQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func NewSessionRepository(db *sql.DB) SessionRepository {
	return SessionRepository{db: db}
}

func (repository SessionRepository) Pending(ctx context.Context, tenantID, agentID string) ([]domaingateway.Message, error) {
	return pendingMessages(ctx, repository.db, tenantID, agentID)
}

func (repository SessionRepository) Open(ctx context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return domaingateway.OpenSession{}, err
	}
	defer tx.Rollback()
	result := domaingateway.OpenSession{TenantID: tenantID, AgentID: agentID}
	result.PolicyDocument, err = effectivePolicy(ctx, tx, tenantID, agentID, scopeType, scopeSelector)
	if err != nil {
		return result, err
	}
	result.SessionID, result.ResumeCursor, err = openControlSession(ctx, tx, tenantID, agentID)
	if err != nil {
		return result, err
	}
	result.Messages, err = pendingMessages(ctx, tx, tenantID, agentID)
	if err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit control session: %w", err)
	}
	return result, nil
}

func effectivePolicy(ctx context.Context, tx *sql.Tx, tenantID, agentID, scopeType, scopeSelector string) ([]byte, error) {
	assigned := `SELECT p.data FROM policy_assignments a JOIN policies p ON p.tenant_id=a.tenant_id AND p.policy_id=a.policy_id AND p.version=a.policy_version WHERE a.tenant_id=$1 AND (a.agent_id=$2 OR (a.agent_id='' AND a.scope_type=$3 AND (a.scope_selector='' OR a.scope_selector=$4))) ORDER BY CASE WHEN a.agent_id=$2 THEN 0 ELSE 1 END,a.updated_at DESC`
	document, found, err := firstPublished(ctx, tx, assigned, tenantID, agentID, scopeType, scopeSelector)
	if err != nil {
		return nil, err
	}
	if found {
		return endpointPolicyDocument(document)
	}
	fallback := `SELECT data FROM policies WHERE tenant_id=$1 ORDER BY version DESC`
	document, found, err = firstPublished(ctx, tx, fallback, tenantID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("read effective policy: %w", sql.ErrNoRows)
	}
	return endpointPolicyDocument(document)
}

func endpointPolicyDocument(document []byte) ([]byte, error) {
	var identity struct {
		PolicyID string `json:"policy_id"`
		Version  uint64 `json:"version"`
	}
	if err := json.Unmarshal(document, &identity); err != nil {
		return nil, fmt.Errorf("decode effective policy identity: %w", err)
	}
	return policypostgres.EndpointDocument(document, domainpolicy.ID(identity.PolicyID), domainpolicy.Version(identity.Version))
}

func firstPublished(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]byte, bool, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, fmt.Errorf("read effective policy: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, false, fmt.Errorf("read effective policy: %w", err)
		}
		var metadata struct {
			Published bool `json:"published"`
		}
		if json.Unmarshal(document, &metadata) == nil && metadata.Published {
			return document, true, nil
		}
	}
	return nil, false, rows.Err()
}
func openControlSession(ctx context.Context, tx *sql.Tx, tenantID, agentID string) (string, string, error) {
	sessionID, now := sessionID(tenantID, agentID), time.Now().UTC()
	var cursor string
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(last_ack_cursor,'') FROM agent_sessions WHERE tenant_id=$1 AND agent_id=$2 ORDER BY last_seen_at DESC LIMIT 1`, tenantID, agentID).Scan(&cursor)
	if err != nil && err != sql.ErrNoRows {
		return "", "", err
	}
	document, _ := json.Marshal(map[string]any{"tenant_id": tenantID, "agent_id": agentID, "session_id": sessionID, "control_transport": "control", "status": "active", "last_ack_cursor": cursor, "last_seen_at": now})
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_sessions (tenant_id,session_id,agent_id,status,control_transport,last_ack_cursor,started_at,last_seen_at,last_control_seen_at,data) VALUES ($1,$2,$3,'active','control',$4,$5,$5,$5,$6) ON CONFLICT (tenant_id,session_id) DO UPDATE SET status='active',control_transport='control',last_seen_at=EXCLUDED.last_seen_at,last_control_seen_at=EXCLUDED.last_control_seen_at,data=EXCLUDED.data`, tenantID, sessionID, agentID, cursor, now, document)
	if err != nil {
		return "", "", fmt.Errorf("open control session: %w", err)
	}
	return sessionID, cursor, nil
}
func pendingMessages(ctx context.Context, queryer messageQueryer, tenantID, agentID string) ([]domaingateway.Message, error) {
	queries := []struct{ kind, query string }{{"response_command", `SELECT response_id,command FROM response_audit WHERE tenant_id=$1 AND agent_id=$2 AND status IN ('pending','pending_approval') ORDER BY created_at`}, {"evidence_pullback", `SELECT request_id,data FROM evidence_pullbacks WHERE tenant_id=$1 AND agent_id=$2 AND status='pending' ORDER BY created_at`}, {"control_command", `SELECT command_id,data FROM control_commands WHERE tenant_id=$1 AND agent_id=$2 AND status IN ('pending','sent') ORDER BY created_at`}}
	result := []domaingateway.Message{}
	for _, item := range queries {
		rows, err := queryer.QueryContext(ctx, item.query, tenantID, agentID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var data []byte
			if err := rows.Scan(&id, &data); err != nil {
				rows.Close()
				return nil, err
			}
			result = append(result, domaingateway.Message{Type: item.kind, ID: id, Document: data})
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func sessionID(tenantID, agentID string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + agentID))
	return hex.EncodeToString(sum[:16])
}
