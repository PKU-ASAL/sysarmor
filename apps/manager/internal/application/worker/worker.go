package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

const maxAttempts = 3

type Worker struct {
	consumer   ports.RawConsumer
	processor  ports.BatchProcessor
	dlq        ports.RawProducer
	rejections ports.CandidateRejectionRecorder
}

func New(consumer ports.RawConsumer, processor ports.BatchProcessor, dlq ports.RawProducer, rejections ports.CandidateRejectionRecorder) *Worker {
	return &Worker{consumer: consumer, processor: processor, dlq: dlq, rejections: rejections}
}

func (worker *Worker) Run(ctx context.Context) error {
	if worker == nil || worker.consumer == nil || worker.processor == nil {
		return fmt.Errorf("worker requires consumer and processor")
	}
	for {
		message, err := worker.consumer.Fetch(ctx)
		if err != nil {
			return err
		}
		if err := worker.process(ctx, message); err != nil {
			return err
		}
	}
}

func (worker *Worker) process(ctx context.Context, message ports.RawMessage) error {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := worker.processor.Process(ctx, message)
		if err == nil {
			return worker.consumer.Commit(ctx, message)
		}
		var permanent ports.PermanentError
		if errors.As(err, &permanent) {
			if permanent.CandidateRejection != nil && worker.rejections != nil {
				if err := worker.rejections.RecordCandidateRejection(ctx, *permanent.CandidateRejection); err != nil {
					return fmt.Errorf("record Candidate reference rejection: %w", err)
				}
			}
			if err := worker.reject(ctx, message, err); err != nil {
				return err
			}
			return worker.consumer.Commit(ctx, message)
		}
		lastErr = err
		if attempt+1 < maxAttempts && !waitRetry(ctx, attempt) {
			return ctx.Err()
		}
	}
	return lastErr
}

func (worker *Worker) reject(ctx context.Context, message ports.RawMessage, cause error) error {
	if worker.dlq == nil {
		return cause
	}
	var permanent ports.PermanentError
	if errors.As(cause, &permanent) && permanent.Message != nil {
		message = *permanent.Message
	}
	message.Topic += ".dlq"
	if err := worker.dlq.Publish(ctx, message); err != nil {
		return fmt.Errorf("publish dead letter: %w", err)
	}
	return nil
}

func waitRetry(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(time.Duration(10*(1<<attempt)) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
