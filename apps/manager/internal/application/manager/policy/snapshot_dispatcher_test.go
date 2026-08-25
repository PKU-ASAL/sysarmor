package policy

import (
	"context"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type snapshotOutboxFake struct {
	items     []ports.PolicySnapshot
	published int
}

func (fake *snapshotOutboxFake) Pending(context.Context, int) ([]ports.PolicySnapshot, error) {
	return fake.items, nil
}
func (fake *snapshotOutboxFake) MarkPublished(context.Context, ports.PolicySnapshot) error {
	fake.published++
	return nil
}
func (*snapshotOutboxFake) RecordFailure(context.Context, ports.PolicySnapshot, string) error {
	return nil
}

type snapshotPublisherFake struct{ published int }

func (fake *snapshotPublisherFake) PublishPolicySnapshot(context.Context, ports.PolicySnapshot) error {
	fake.published++
	return nil
}

func TestSnapshotDispatcherMarksKafkaAcknowledgedItems(t *testing.T) {
	outbox := &snapshotOutboxFake{items: []ports.PolicySnapshot{{}}}
	publisher := &snapshotPublisherFake{}
	if err := NewSnapshotDispatcher(outbox, publisher).RunOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if publisher.published != 1 || outbox.published != 1 {
		t.Fatalf("publisher=%d outbox=%d", publisher.published, outbox.published)
	}
}
