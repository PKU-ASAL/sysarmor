package localapi

import (
	"context"
	"testing"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	"google.golang.org/grpc"
)

type recordingTelemetryReader struct {
	events     []*dataplanev1.EventFrame
	eventCalls int
}

func (*recordingTelemetryReader) Identity() TelemetryIdentity {
	return TelemetryIdentity{TenantID: "tenant-a", AgentID: "agent-a"}
}

func (r *recordingTelemetryReader) EventByID(context.Context, string) (*dataplanev1.EventFrame, bool, error) {
	r.eventCalls++
	return &dataplanev1.EventFrame{}, true, nil
}

func (r *recordingTelemetryReader) RecentEvents(context.Context, EventQuery) ([]*dataplanev1.EventFrame, error) {
	return r.events, nil
}

func (*recordingTelemetryReader) RecentSignals(context.Context, SignalQuery) ([]*dataplanev1.SignalFrame, error) {
	return nil, nil
}

func (*recordingTelemetryReader) WatchEvents(ctx context.Context) <-chan *dataplanev1.EventFrame {
	out := make(chan *dataplanev1.EventFrame)
	close(out)
	return out
}

func (*recordingTelemetryReader) WatchSignals(ctx context.Context) <-chan *dataplanev1.SignalFrame {
	out := make(chan *dataplanev1.SignalFrame)
	close(out)
	return out
}

type recordingEventStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*controlplanev1.EventFrame
}

func (s *recordingEventStream) Context() context.Context { return s.ctx }

func (s *recordingEventStream) Send(frame *controlplanev1.EventFrame) error {
	s.sent = append(s.sent, frame)
	return nil
}

func TestHandlerWatchEventsOwnsFilteringAndIdentityEncoding(t *testing.T) {
	reader := &recordingTelemetryReader{events: []*dataplanev1.EventFrame{
		{Sequence: 1, Event: &eventv1.CanonicalEvent{Id: "ignored", Behavior: "file.read"}},
		{Sequence: 2, ObservedAt: "2026-08-06T00:00:00Z", Event: &eventv1.CanonicalEvent{Id: "event-a", Behavior: "process.exec"}},
	}}
	handler := NewHandler(Dependencies{Telemetry: reader})
	stream := &recordingEventStream{ctx: t.Context()}

	err := handler.WatchEvents(&controlplanev1.WatchEventsRequest{
		Behavior: "process.exec", IncludeRecent: true, SnapshotOnly: true,
	}, stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetEvent().GetId() != "event-a" ||
		stream.sent[0].GetTenantId() != "tenant-a" || stream.sent[0].GetAgentId() != "agent-a" {
		t.Fatalf("sent=%+v", stream.sent)
	}
}
