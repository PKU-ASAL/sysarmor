package ports

import (
	"context"
	"time"
)

type BatchEnvelope struct {
	TenantID, AgentID, HostID, BatchID string
	Transport, Topic, Key              string
	Payload                            []byte
}

type GatewaySession struct {
	TenantID, AgentID, SessionID, Cursor string
	LastSeenAt                           time.Time
}

type BatchPublisher interface {
	Publish(context.Context, BatchEnvelope) error
}
type GatewaySessionStore interface {
	IsDuplicate(context.Context, string, string, string) (bool, error)
	RecordBatch(context.Context, BatchEnvelope) (GatewaySession, error)
}
type HotSessionWriter interface {
	Touch(context.Context, GatewaySession) error
}
