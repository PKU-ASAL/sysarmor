package localapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type TelemetryIdentity struct {
	TenantID string
	AgentID  string
}

type EventQuery struct {
	Behavior      string
	AfterSequence uint64
	Limit         int
}

type SignalQuery struct {
	RuleID string
	Limit  int
}

type TelemetryReader interface {
	Identity() TelemetryIdentity
	EventByID(context.Context, string) (*dataplanev1.EventFrame, bool, error)
	RecentEvents(context.Context, EventQuery) ([]*dataplanev1.EventFrame, error)
	RecentSignals(context.Context, SignalQuery) ([]*dataplanev1.SignalFrame, error)
	WatchEvents(context.Context) <-chan *dataplanev1.EventFrame
	WatchSignals(context.Context) <-chan *dataplanev1.SignalFrame
}

func (h *Handler) GetEvent(ctx context.Context, req *controlplanev1.GetEventRequest) (*controlplanev1.EventGetResponse, error) {
	if err := h.validate(req.GetContext()); err != nil {
		return nil, err
	}
	if h.deps.Telemetry == nil {
		return nil, fmt.Errorf("local api telemetry handler is unavailable")
	}
	eventID := strings.TrimSpace(req.GetEventId())
	if eventID == "" {
		return nil, fmt.Errorf("event id is required")
	}
	frame, ok, err := h.deps.Telemetry.EventByID(ctx, eventID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("event %q not found in telemetry buffer", eventID)
	}
	return &controlplanev1.EventGetResponse{Frame: eventFrame(h.deps.Telemetry.Identity(), frame)}, nil
}

func (h *Handler) WatchEvents(req *controlplanev1.WatchEventsRequest, stream controlplanev1.AgentControlPlaneService_WatchEventsServer) error {
	if err := h.validate(req.GetContext()); err != nil {
		return err
	}
	if h.deps.Telemetry == nil {
		return fmt.Errorf("local api telemetry handler is unavailable")
	}
	sent, err := h.replayEvents(req, stream)
	if err != nil || req.GetSnapshotOnly() || limitReached(req.GetLimit(), sent) {
		return err
	}
	for frame := range h.deps.Telemetry.WatchEvents(stream.Context()) {
		matched, err := h.sendEvent(req, stream, frame)
		if err != nil {
			return err
		}
		if matched {
			sent++
		}
		if limitReached(req.GetLimit(), sent) {
			return nil
		}
	}
	return stream.Context().Err()
}

func (h *Handler) replayEvents(req *controlplanev1.WatchEventsRequest, stream controlplanev1.AgentControlPlaneService_WatchEventsServer) (uint32, error) {
	if !req.GetIncludeRecent() {
		return 0, nil
	}
	frames, err := h.deps.Telemetry.RecentEvents(stream.Context(), EventQuery{
		Behavior: req.GetBehavior(), AfterSequence: req.GetFilter().GetAfterSequence(), Limit: int(req.GetLimit()),
	})
	if err != nil {
		return 0, err
	}
	var sent uint32
	for _, frame := range frames {
		matched, err := h.sendEvent(req, stream, frame)
		if err != nil {
			return sent, err
		}
		if matched {
			sent++
		}
		if limitReached(req.GetLimit(), sent) {
			break
		}
	}
	return sent, nil
}

func (h *Handler) sendEvent(req *controlplanev1.WatchEventsRequest, stream controlplanev1.AgentControlPlaneService_WatchEventsServer, frame *dataplanev1.EventFrame) (bool, error) {
	out := eventFrame(h.deps.Telemetry.Identity(), frame)
	if !eventFrameMatches(out, req.GetBehavior(), req.GetFilter()) {
		return false, nil
	}
	return true, stream.Send(out)
}

func (h *Handler) WatchSignals(req *controlplanev1.WatchSignalsRequest, stream controlplanev1.AgentControlPlaneService_WatchSignalsServer) error {
	if err := h.validate(req.GetContext()); err != nil {
		return err
	}
	if h.deps.Telemetry == nil {
		return fmt.Errorf("local api telemetry handler is unavailable")
	}
	sent, err := h.replaySignals(req, stream)
	if err != nil || req.GetSnapshotOnly() || limitReached(req.GetLimit(), sent) {
		return err
	}
	for frame := range h.deps.Telemetry.WatchSignals(stream.Context()) {
		matched, err := h.sendSignal(req, stream, frame)
		if err != nil {
			return err
		}
		if matched {
			sent++
		}
		if limitReached(req.GetLimit(), sent) {
			return nil
		}
	}
	return stream.Context().Err()
}

func (h *Handler) replaySignals(req *controlplanev1.WatchSignalsRequest, stream controlplanev1.AgentControlPlaneService_WatchSignalsServer) (uint32, error) {
	if !req.GetIncludeRecent() {
		return 0, nil
	}
	frames, err := h.deps.Telemetry.RecentSignals(stream.Context(), SignalQuery{RuleID: req.GetRuleId(), Limit: int(req.GetLimit())})
	if err != nil {
		return 0, err
	}
	var sent uint32
	for _, frame := range frames {
		matched, err := h.sendSignal(req, stream, frame)
		if err != nil {
			return sent, err
		}
		if matched {
			sent++
		}
		if limitReached(req.GetLimit(), sent) {
			break
		}
	}
	return sent, nil
}

func (h *Handler) sendSignal(req *controlplanev1.WatchSignalsRequest, stream controlplanev1.AgentControlPlaneService_WatchSignalsServer, frame *dataplanev1.SignalFrame) (bool, error) {
	out := signalFrame(h.deps.Telemetry.Identity(), frame)
	if !signalFrameMatches(out, req.GetRuleId(), req.GetWhere(), req.GetFilter()) {
		return false, nil
	}
	return true, stream.Send(out)
}

func limitReached(limit, sent uint32) bool {
	return limit > 0 && sent >= limit
}

func eventFrame(identity TelemetryIdentity, frame *dataplanev1.EventFrame) *controlplanev1.EventFrame {
	if frame == nil {
		return &controlplanev1.EventFrame{TenantId: identity.TenantID, AgentId: identity.AgentID}
	}
	return &controlplanev1.EventFrame{
		TenantId: identity.TenantID, AgentId: identity.AgentID, Sequence: frame.GetSequence(),
		ObservedAt: frame.GetObservedAt(), Event: frame.GetEvent(),
	}
}

func signalFrame(identity TelemetryIdentity, frame *dataplanev1.SignalFrame) *controlplanev1.SignalFrame {
	if frame == nil {
		return &controlplanev1.SignalFrame{TenantId: identity.TenantID, AgentId: identity.AgentID}
	}
	return &controlplanev1.SignalFrame{
		TenantId: identity.TenantID, AgentId: identity.AgentID, Sequence: frame.GetSequence(),
		ObservedAt: frame.GetObservedAt(), Signal: frame.GetSignal(),
	}
}

func eventFrameMatches(frame *controlplanev1.EventFrame, behavior string, filter *controlplanev1.WatchFilter) bool {
	if frame == nil || !eventMatches(frame.GetEvent(), behavior) {
		return false
	}
	return frameMatches(frame.GetSequence(), frame.GetObservedAt(), frame.GetEvent().GetLabels(), filter)
}

func eventMatches(event *eventv1.CanonicalEvent, behavior string) bool {
	if event == nil {
		return false
	}
	behavior = strings.TrimSpace(strings.ToLower(behavior))
	return behavior == "" || strings.TrimSpace(strings.ToLower(event.GetBehavior())) == behavior
}

func signalFrameMatches(frame *controlplanev1.SignalFrame, ruleID, where string, filter *controlplanev1.WatchFilter) bool {
	if frame == nil || !signalMatches(frame.GetSignal(), ruleID, where) {
		return false
	}
	return frameMatches(frame.GetSequence(), frame.GetObservedAt(), frame.GetSignal().GetLabels(), filter)
}

func signalMatches(signal *signalv1.Signal, ruleID, where string) bool {
	if signal == nil || strings.TrimSpace(ruleID) != "" && signal.GetName() != strings.TrimSpace(ruleID) {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(where)) {
	case "":
		return true
	case "endpoint":
		return signal.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT
	case "cloud":
		return signal.GetWhere() == signalv1.SignalWhere_SIGNAL_WHERE_CLOUD
	default:
		return false
	}
}

func frameMatches(sequence uint64, observedAt string, labels map[string]string, filter *controlplanev1.WatchFilter) bool {
	if filter == nil {
		return true
	}
	if filter.GetAfterSequence() > 0 && sequence <= filter.GetAfterSequence() {
		return false
	}
	if !observedAtMatches(observedAt, filter.GetSinceObservedAt(), filter.GetUntilObservedAt()) {
		return false
	}
	for key, want := range filter.GetLabels() {
		if labels[key] != want {
			return false
		}
	}
	return true
}

func observedAtMatches(observedAt, since, until string) bool {
	if strings.TrimSpace(since) == "" && strings.TrimSpace(until) == "" {
		return true
	}
	ts, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil {
		return false
	}
	if strings.TrimSpace(since) != "" {
		start, err := time.Parse(time.RFC3339Nano, since)
		if err != nil || ts.Before(start) {
			return false
		}
	}
	if strings.TrimSpace(until) != "" {
		end, err := time.Parse(time.RFC3339Nano, until)
		if err != nil || !ts.Before(end) {
			return false
		}
	}
	return true
}
