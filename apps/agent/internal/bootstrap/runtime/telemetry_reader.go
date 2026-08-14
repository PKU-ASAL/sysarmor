package runtime

import (
	"context"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/inbound/unix"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func (s *localTelemetryService) Identity() localapi.TelemetryIdentity {
	identity := s.runner.currentIdentity()
	return localapi.TelemetryIdentity{TenantID: identity.TenantID, AgentID: identity.AgentID}
}

func (s *localTelemetryService) EventByID(ctx context.Context, eventID string) (*dataplanev1.EventFrame, bool, error) {
	if s.runner.localStore != nil {
		frames, err := s.runner.localStore.QueryEvents(ctx, sqlite.EventQuery{Limit: 1000})
		if err == nil {
			for _, frame := range frames {
				if frame.GetEvent().GetId() == eventID {
					return frame, true, nil
				}
			}
		}
	}
	for _, frame := range s.bus.SnapshotEvents() {
		if frame.GetEvent().GetId() == eventID {
			return frame, true, nil
		}
	}
	return nil, false, nil
}

func (s *localTelemetryService) RecentEvents(ctx context.Context, query localapi.EventQuery) ([]*dataplanev1.EventFrame, error) {
	if s.runner.localStore == nil {
		return s.bus.SnapshotEvents(), nil
	}
	limit := query.Limit
	if limit == 0 {
		limit = 100
	}
	return s.runner.localStore.QueryEvents(ctx, sqlite.EventQuery{
		Behavior: query.Behavior, AfterSequence: query.AfterSequence, Limit: limit,
	})
}

func (s *localTelemetryService) RecentSignals(ctx context.Context, query localapi.SignalQuery) ([]*dataplanev1.SignalFrame, error) {
	if s.runner.localStore == nil {
		return s.bus.SnapshotSignals(), nil
	}
	limit := query.Limit
	if limit == 0 {
		limit = 100
	}
	return s.runner.localStore.QuerySignals(ctx, sqlite.SignalQuery{RuleID: query.RuleID, Limit: limit})
}

func (s *localTelemetryService) WatchEvents(ctx context.Context) <-chan *dataplanev1.EventFrame {
	return s.bus.WatchEvents(ctx)
}

func (s *localTelemetryService) WatchSignals(ctx context.Context) <-chan *dataplanev1.SignalFrame {
	return s.bus.WatchSignals(ctx)
}
