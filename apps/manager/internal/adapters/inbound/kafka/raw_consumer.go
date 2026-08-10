package kafka

import (
	"context"
	"errors"
	"strings"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

var ErrDisabled = errors.New("kafka worker is disabled")

type RawConsumer struct{ reader *kafkago.Reader }

func NewRawConsumer(brokers []string, topic, groupID string) (*RawConsumer, error) {
	clean := cleanBrokers(brokers)
	if len(clean) == 0 || strings.TrimSpace(topic) == "" || strings.TrimSpace(groupID) == "" {
		return nil, ErrDisabled
	}
	return &RawConsumer{reader: kafkago.NewReader(kafkago.ReaderConfig{Brokers: clean, Topic: topic, GroupID: groupID})}, nil
}

func (consumer *RawConsumer) Fetch(ctx context.Context) (ports.RawMessage, error) {
	if consumer == nil || consumer.reader == nil {
		return ports.RawMessage{}, ErrDisabled
	}
	message, err := consumer.reader.FetchMessage(ctx)
	if err != nil {
		return ports.RawMessage{}, err
	}
	return ports.RawMessage{Topic: message.Topic, Key: string(message.Key), Partition: message.Partition, Offset: message.Offset, Value: message.Value}, nil
}

func (consumer *RawConsumer) Commit(ctx context.Context, message ports.RawMessage) error {
	if consumer == nil || consumer.reader == nil {
		return ErrDisabled
	}
	return consumer.reader.CommitMessages(ctx, kafkago.Message{Topic: message.Topic, Partition: message.Partition, Offset: message.Offset, Key: []byte(message.Key), Value: message.Value})
}

func (consumer *RawConsumer) Close() error {
	if consumer == nil || consumer.reader == nil {
		return nil
	}
	return consumer.reader.Close()
}

func cleanBrokers(brokers []string) []string {
	clean := make([]string, 0, len(brokers))
	for _, broker := range brokers {
		if value := strings.TrimSpace(broker); value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}

func WaitForConsumer(ctx context.Context, open func() (*RawConsumer, error)) (*RawConsumer, error) {
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		consumer, err := open()
		if err == nil {
			return consumer, nil
		}
		lastErr = err
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}
