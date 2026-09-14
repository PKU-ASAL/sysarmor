package sqlite

import (
	"context"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type EventQuery struct {
	Behavior      string
	AfterSequence uint64
	Limit         int
}

func (s *Store) QueryEvents(ctx context.Context, query EventQuery) ([]*dataplanev1.EventFrame, error) {
	batches, err := s.ReadBatches(ctx, ReadOptions{Limit: 1_000_000, FromSequence: query.AfterSequence + 1})
	if err != nil {
		return nil, err
	}
	limit := query.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	var frames []*dataplanev1.EventFrame
	for _, stored := range batches {
		for _, frame := range stored.Batch.GetEvents() {
			if frame.GetSequence() <= query.AfterSequence {
				continue
			}
			if query.Behavior != "" && frame.GetEvent().GetBehavior() != query.Behavior {
				continue
			}
			frames = append(frames, frame)
		}
	}
	if len(frames) > limit {
		frames = frames[len(frames)-limit:]
	}
	return frames, nil
}
