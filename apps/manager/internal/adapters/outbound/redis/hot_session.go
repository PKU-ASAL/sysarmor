package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type HotSessionWriter struct {
	client *goredis.Client
	ttl    time.Duration
}

func NewHotSessionWriter(address string, ttl time.Duration) (*HotSessionWriter, error) {
	if address == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &HotSessionWriter{client: goredis.NewClient(&goredis.Options{Addr: address}), ttl: ttl}, nil
}
func (writer *HotSessionWriter) Touch(ctx context.Context, session ports.GatewaySession) error {
	if writer == nil || writer.client == nil {
		return fmt.Errorf("redis hot session writer is not configured")
	}
	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}
	key := "sysarmor:agent_session:" + session.TenantID + ":" + session.AgentID
	return writer.client.Set(ctx, key, payload, writer.ttl).Err()
}
func (writer *HotSessionWriter) Close() error {
	if writer == nil || writer.client == nil {
		return nil
	}
	return writer.client.Close()
}
