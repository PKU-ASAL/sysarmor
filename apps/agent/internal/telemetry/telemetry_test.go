package telemetry

import (
	"context"
	"testing"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
)

func TestBusSnapshotsAndWatchesFrames(t *testing.T) {
	bus := NewBus(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := bus.WatchEvents(ctx)
	bus.PublishEvent(eventFrame(1, "ev-1"))
	got := <-watch
	if got.GetEvent().GetId() != "ev-1" {
		t.Fatalf("watch event = %+v", got)
	}
	bus.PublishEvent(eventFrame(2, "ev-2"))
	bus.PublishEvent(eventFrame(3, "ev-3"))
	snapshot := bus.SnapshotEvents()
	if len(snapshot) != 2 || snapshot[0].GetEvent().GetId() != "ev-2" || snapshot[1].GetEvent().GetId() != "ev-3" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if stats := bus.Stats(); stats.EventDropped != 1 || stats.EventBuffered != 2 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestBatcherFlushesByCount(t *testing.T) {
	batcher := NewBatcher(func(now time.Time) *dataplanev1.DataBatch {
		return &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{TenantId: "default", AgentId: "agent-a", CreatedAtUnixNano: now.UnixNano()}}
	}, 2, time.Hour, 4)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(1, "ev-1")}})
	batcher.Add(&dataplanev1.DataBatch{Signals: []*dataplanev1.SignalFrame{signalFrame(1, "sig-1")}})
	select {
	case batch := <-batcher.Batches():
		if batch.GetSchemaVersion() != schema.DataPlaneCurrent {
			t.Fatalf("schema version = %q", batch.GetSchemaVersion())
		}
		if len(batch.GetEvents()) != 1 || len(batch.GetSignals()) != 1 || batch.GetHeader().GetEventCount() != 1 || batch.GetHeader().GetSignalCount() != 1 {
			t.Fatalf("batch = %+v", batch)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for flushed batch")
	}
}

func TestBatcherFlushAndApplyBlocksConcurrentAddUntilApplyCompletes(t *testing.T) {
	identity := "old"
	applyStarted := make(chan struct{})
	releaseApply := make(chan struct{})
	batcher := NewBatcher(func(time.Time) *dataplanev1.DataBatch {
		return &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{AgentId: identity}}
	}, 10, time.Hour, 4)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 1}}})

	transitionDone := make(chan struct{})
	go func() {
		batcher.FlushAndApply("identity", func() {
			close(applyStarted)
			<-releaseApply
			identity = "new"
		})
		close(transitionDone)
	}()
	<-applyStarted

	addDone := make(chan struct{})
	go func() {
		batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{{Sequence: 2}}})
		close(addDone)
	}()
	select {
	case <-addDone:
		t.Fatal("Add completed before identity transition")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseApply)
	<-transitionDone
	<-addDone
	batcher.Flush("test")

	oldBatch := <-batcher.Batches()
	newBatch := <-batcher.Batches()
	if oldBatch.GetHeader().GetAgentId() != "old" || newBatch.GetHeader().GetAgentId() != "new" {
		t.Fatalf("batch identities = %q/%q", oldBatch.GetHeader().GetAgentId(), newBatch.GetHeader().GetAgentId())
	}
}

func TestBatcherReconfigureSealsPendingBatchAndUsesNewLimits(t *testing.T) {
	batcher := NewBatcher(nil, 10, time.Hour, 4, 256<<10)
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(1, "ev-1")}})
	batcher.Reconfigure(BatchSettings{MaxItems: 2, MaxBytes: 128 << 10, FlushInterval: 2 * time.Second})
	first := <-batcher.Batches()
	if len(first.GetEvents()) != 1 {
		t.Fatalf("sealed batch=%+v", first)
	}
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(2, "ev-2")}})
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(3, "ev-3")}})
	second := <-batcher.Batches()
	if len(second.GetEvents()) != 2 || batcher.Stats().MaxBytes != 128<<10 {
		t.Fatalf("reconfigured batch=%+v stats=%+v", second, batcher.Stats())
	}
}

func TestSenderRecordsAcceptedBatch(t *testing.T) {
	batcher := NewBatcher(nil, 10, time.Hour, 1)
	appender := &recordingAppender{}
	sender := &Sender{Appender: appender, Batcher: batcher}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sender.Run(ctx)
	}()
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(1, "ev-1")}})
	batcher.Flush("test")
	deadline := time.After(time.Second)
	for {
		if sender.Stats().SentBatches == 1 {
			cancel()
			<-done
			return
		}
		select {
		case <-deadline:
			t.Fatalf("sender stats = %+v appends=%d", sender.Stats(), appender.appends)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestSenderDrainsClosedBatcher(t *testing.T) {
	batcher := NewBatcher(nil, 10, time.Hour, 4)
	appender := &recordingAppender{}
	sender := &Sender{Appender: appender, Batcher: batcher}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		sender.Run(ctx)
	}()
	batcher.Add(&dataplanev1.DataBatch{Events: []*dataplanev1.EventFrame{eventFrame(1, "ev-1")}})
	batcher.CloseAndFlush("shutdown")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for sender drain")
	}
	stats := sender.Stats()
	if !stats.Drained || stats.SentBatches != 1 || appender.appends != 1 {
		t.Fatalf("sender stats = %+v appends=%d", stats, appender.appends)
	}
	if !batcher.Stats().Closed {
		t.Fatalf("batcher stats = %+v", batcher.Stats())
	}
}

type recordingAppender struct {
	appends int
}

func (r *recordingAppender) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	r.appends++
	return &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_ACCEPTED, Accepted: true, BatchId: batch.GetHeader().GetBatchId()}, nil
}

func eventFrame(seq uint64, id string) *dataplanev1.EventFrame {
	return &dataplanev1.EventFrame{Sequence: seq, Event: &eventv1.CanonicalEvent{Id: id}}
}

func signalFrame(seq uint64, id string) *dataplanev1.SignalFrame {
	return &dataplanev1.SignalFrame{Sequence: seq, Signal: &signalv1.Signal{Id: id, Name: id}}
}
