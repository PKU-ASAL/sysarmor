package policy

import (
	"context"
	"fmt"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type SnapshotDispatcher struct {
	outbox    ports.PolicySnapshotOutbox
	publisher ports.PolicySnapshotPublisher
}

func NewSnapshotDispatcher(outbox ports.PolicySnapshotOutbox, publisher ports.PolicySnapshotPublisher) *SnapshotDispatcher {
	return &SnapshotDispatcher{outbox: outbox, publisher: publisher}
}

func (dispatcher *SnapshotDispatcher) RunOnce(ctx context.Context) error {
	items, err := dispatcher.outbox.Pending(ctx, 100)
	if err != nil {
		return fmt.Errorf("list policy snapshot outbox: %w", err)
	}
	for _, item := range items {
		if err := dispatcher.publisher.PublishPolicySnapshot(ctx, item); err != nil {
			_ = dispatcher.outbox.RecordFailure(ctx, item, err.Error())
			return fmt.Errorf("publish policy snapshot: %w", err)
		}
		if err := dispatcher.outbox.MarkPublished(ctx, item); err != nil {
			return fmt.Errorf("mark policy snapshot published: %w", err)
		}
	}
	return nil
}
