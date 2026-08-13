package kafka

import (
	"context"
	"fmt"
	"strings"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type RawProducer struct{ writer *kafkago.Writer }

func NewRawProducer(brokers []string) (*RawProducer, error) {
	clean := make([]string, 0, len(brokers))
	for _, broker := range brokers {
		if value := strings.TrimSpace(broker); value != "" {
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("kafka brokers are required")
	}
	return &RawProducer{writer: &kafkago.Writer{Addr: kafkago.TCP(clean...), Balancer: &kafkago.Hash{}, RequiredAcks: kafkago.RequireAll, Async: false}}, nil
}

func (producer *RawProducer) Publish(ctx context.Context, message ports.RawMessage) error {
	if producer == nil || producer.writer == nil {
		return fmt.Errorf("kafka producer is not configured")
	}
	return producer.writer.WriteMessages(ctx, kafkago.Message{Topic: message.Topic, Key: []byte(message.Key), Value: message.Value})
}

func (producer *RawProducer) Close() error {
	if producer == nil || producer.writer == nil {
		return nil
	}
	return producer.writer.Close()
}
