package kafka

import (
	"context"
	"fmt"
	"strings"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type BatchPublisher struct{ writer *kafkago.Writer }

func NewBatchPublisher(brokers []string) (*BatchPublisher, error) {
	clean := make([]string, 0, len(brokers))
	for _, value := range brokers {
		if value = strings.TrimSpace(value); value != "" {
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("kafka brokers are required")
	}
	return &BatchPublisher{writer: &kafkago.Writer{Addr: kafkago.TCP(clean...), Balancer: &kafkago.Hash{}, RequiredAcks: kafkago.RequireAll, Async: false}}, nil
}
func (publisher *BatchPublisher) Publish(ctx context.Context, batch ports.BatchEnvelope) error {
	if publisher == nil || publisher.writer == nil {
		return fmt.Errorf("kafka publisher is not configured")
	}
	return publisher.writer.WriteMessages(ctx, kafkago.Message{Topic: batch.Topic, Key: []byte(batch.Key), Value: append([]byte(nil), batch.Payload...)})
}
func (publisher *BatchPublisher) Close() error {
	if publisher == nil || publisher.writer == nil {
		return nil
	}
	return publisher.writer.Close()
}
