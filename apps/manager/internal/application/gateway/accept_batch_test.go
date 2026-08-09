package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type fakePublisher struct {
	calls int
	err   error
}

func (fake *fakePublisher) Publish(context.Context, ports.BatchEnvelope) error {
	fake.calls++
	return fake.err
}

type fakeSessions struct {
	duplicate bool
	recorded  int
	err       error
}

func (fake *fakeSessions) IsDuplicate(context.Context, string, string, string) (bool, error) {
	return fake.duplicate, fake.err
}
func (fake *fakeSessions) RecordBatch(context.Context, ports.BatchEnvelope) (ports.GatewaySession, error) {
	fake.recorded++
	return ports.GatewaySession{Cursor: "batch-a"}, fake.err
}

func TestAcceptPublishesBeforeRecordingSession(t *testing.T) {
	publisher, sessions := &fakePublisher{}, &fakeSessions{}
	result, err := NewBatchAcceptor(publisher, sessions, nil).Accept(context.Background(), validBatch())
	if err != nil || result.Duplicate || publisher.calls != 1 || sessions.recorded != 1 {
		t.Fatalf("result=%+v publish=%d record=%d err=%v", result, publisher.calls, sessions.recorded, err)
	}
}
func TestAcceptDuplicateSkipsPublishAndRecordsCursor(t *testing.T) {
	publisher, sessions := &fakePublisher{}, &fakeSessions{duplicate: true}
	result, err := NewBatchAcceptor(publisher, sessions, nil).Accept(context.Background(), validBatch())
	if err != nil || !result.Duplicate || publisher.calls != 0 || sessions.recorded != 1 {
		t.Fatalf("result=%+v publish=%d record=%d err=%v", result, publisher.calls, sessions.recorded, err)
	}
}
func TestAcceptPublishFailureDoesNotAdvanceSession(t *testing.T) {
	publisher, sessions := &fakePublisher{err: errors.New("down")}, &fakeSessions{}
	if _, err := NewBatchAcceptor(publisher, sessions, nil).Accept(context.Background(), validBatch()); err == nil || sessions.recorded != 0 {
		t.Fatalf("record=%d err=%v", sessions.recorded, err)
	}
}
func validBatch() ports.BatchEnvelope {
	return ports.BatchEnvelope{TenantID: "tenant-a", AgentID: "agent-a", HostID: "host-a", BatchID: "batch-a", Payload: []byte("data")}
}
