package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestWorkerRetriesBeforeCommit(t *testing.T) {
	consumer := &workerConsumer{messages: []ports.RawMessage{{Key: "batch-a"}}}
	processor := &workerProcessor{failures: 2}
	if err := New(consumer, processor, nil).Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if processor.attempts != 3 || consumer.commits != 1 {
		t.Fatalf("attempts=%d commits=%d", processor.attempts, consumer.commits)
	}
}

func TestWorkerSendsPermanentFailureToDLQThenCommits(t *testing.T) {
	consumer := &workerConsumer{messages: []ports.RawMessage{{Topic: "raw", Key: "batch-a", Value: []byte("bad")}}}
	processor := &workerProcessor{err: ports.PermanentError{Err: errors.New("invalid batch")}}
	dlq := &workerProducer{}
	if err := New(consumer, processor, dlq).Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(dlq.messages) != 1 || consumer.commits != 1 {
		t.Fatalf("dlq=%+v commits=%d", dlq.messages, consumer.commits)
	}
}

func TestWorkerReturnsTransientFailureWithoutCommit(t *testing.T) {
	consumer := &workerConsumer{messages: []ports.RawMessage{{Key: "batch-a"}}}
	processor := &workerProcessor{err: errors.New("database unavailable")}
	if err := New(consumer, processor, nil).Run(context.Background()); err == nil || consumer.commits != 0 {
		t.Fatalf("err=%v commits=%d", err, consumer.commits)
	}
}

type workerConsumer struct {
	messages []ports.RawMessage
	commits  int
}

func (consumer *workerConsumer) Fetch(context.Context) (ports.RawMessage, error) {
	if len(consumer.messages) == 0 {
		return ports.RawMessage{}, context.Canceled
	}
	message := consumer.messages[0]
	consumer.messages = consumer.messages[1:]
	return message, nil
}

func (consumer *workerConsumer) Commit(context.Context, ports.RawMessage) error {
	consumer.commits++
	return nil
}

type workerProcessor struct {
	failures, attempts int
	err                error
}

func (processor *workerProcessor) Process(context.Context, ports.RawMessage) error {
	processor.attempts++
	if processor.failures > 0 {
		processor.failures--
		return errors.New("transient")
	}
	return processor.err
}

type workerProducer struct{ messages []ports.RawMessage }

func (producer *workerProducer) Publish(_ context.Context, message ports.RawMessage) error {
	producer.messages = append(producer.messages, message)
	return nil
}
