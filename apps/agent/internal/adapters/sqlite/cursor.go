package sqlite

import (
	"context"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

type SequenceCursor struct {
	Event  uint64
	Signal uint64
}

func (s *Store) SequenceCursor(ctx context.Context) (SequenceCursor, error) {
	if err := ctx.Err(); err != nil {
		return SequenceCursor{}, err
	}
	s.segmentMu.Lock()
	defer s.segmentMu.Unlock()
	return s.cursor, nil
}

func (s *Store) advanceSequenceCursor(batch *dataplanev1.DataBatch) {
	header := batch.GetHeader()
	if header.GetEventSeqEnd() > s.cursor.Event {
		s.cursor.Event = header.GetEventSeqEnd()
	}
	if header.GetSignalSeqEnd() > s.cursor.Signal {
		s.cursor.Signal = header.GetSignalSeqEnd()
	}
}

func (s *Store) loadSequenceCursor(ctx context.Context) error {
	var persisted SequenceCursor
	if err := s.db.QueryRowContext(ctx, `SELECT event_sequence,signal_sequence FROM sequence_cursor WHERE singleton=1`).Scan(
		&persisted.Event, &persisted.Signal,
	); err != nil {
		return err
	}
	if persisted.Event > s.cursor.Event {
		s.cursor.Event = persisted.Event
	}
	if persisted.Signal > s.cursor.Signal {
		s.cursor.Signal = persisted.Signal
	}
	return nil
}

func (s *Store) persistSequenceCursor(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sequence_cursor
SET event_sequence=MAX(event_sequence,?),signal_sequence=MAX(signal_sequence,?)
WHERE singleton=1`, s.cursor.Event, s.cursor.Signal)
	return err
}
