package kafka

import (
	"context"
	"errors"
	"testing"
)

func TestRawConsumerWatchesTopicsCreatedAfterStartup(t *testing.T) {
	consumer, err := NewRawConsumer([]string{"kafka:9092"}, "raw", "worker")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })

	if !consumer.reader.Config().WatchPartitionChanges {
		t.Fatal("RawConsumer does not rebalance when the topic is created after startup")
	}
}

func TestWaitForTopicReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WaitForTopic(ctx, []string{"kafka:9092"}, "raw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForTopic() error = %v, want context canceled", err)
	}
}
