package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type BatchAcceptance struct {
	Duplicate bool
	Session   ports.GatewaySession
}
type BatchAcceptor struct {
	publisher ports.BatchPublisher
	sessions  ports.GatewaySessionStore
	hot       ports.HotSessionWriter
	metrics   *BatchMetrics
}

func NewBatchAcceptor(publisher ports.BatchPublisher, sessions ports.GatewaySessionStore, hot ports.HotSessionWriter, metrics ...*BatchMetrics) *BatchAcceptor {
	service := &BatchAcceptor{publisher: publisher, sessions: sessions, hot: hot}
	if len(metrics) > 0 {
		service.metrics = metrics[0]
	}
	return service
}

func (service *BatchAcceptor) Accept(ctx context.Context, batch ports.BatchEnvelope) (BatchAcceptance, error) {
	if service.metrics != nil {
		service.metrics.recordReceived()
	}
	if err := validateBatch(batch); err != nil {
		return BatchAcceptance{}, err
	}
	duplicate, err := service.sessions.IsDuplicate(ctx, batch.TenantID, batch.AgentID, batch.BatchID)
	if err != nil {
		return BatchAcceptance{}, fmt.Errorf("check duplicate batch: %w", err)
	}
	if !duplicate {
		if err := service.publisher.Publish(ctx, batch); err != nil {
			if service.metrics != nil {
				service.metrics.recordPublishFailed()
			}
			return BatchAcceptance{}, fmt.Errorf("publish batch: %w", err)
		}
		if service.metrics != nil {
			service.metrics.recordPublished()
		}
	}
	session, err := service.sessions.RecordBatch(ctx, batch)
	if err != nil {
		return BatchAcceptance{}, fmt.Errorf("record batch session: %w", err)
	}
	if service.hot != nil {
		if err := service.hot.Touch(ctx, session); err != nil {
			return BatchAcceptance{}, fmt.Errorf("touch hot session: %w", err)
		}
	}
	return BatchAcceptance{Duplicate: duplicate, Session: session}, nil
}

func validateBatch(batch ports.BatchEnvelope) error {
	missing := make([]string, 0, 4)
	if strings.TrimSpace(batch.TenantID) == "" {
		missing = append(missing, "tenant_id")
	}
	if strings.TrimSpace(batch.AgentID) == "" {
		missing = append(missing, "agent_id")
	}
	if strings.TrimSpace(batch.HostID) == "" {
		missing = append(missing, "host_id")
	}
	if strings.TrimSpace(batch.BatchID) == "" {
		missing = append(missing, "batch_id")
	}
	if len(missing) > 0 {
		return fmt.Errorf("batch identity missing %s", strings.Join(missing, ", "))
	}
	return nil
}
