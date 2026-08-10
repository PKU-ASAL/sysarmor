package ports

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type RawMessage struct {
	Topic, Key string
	Partition  int
	Offset     int64
	Value      []byte
}

type RawConsumer interface {
	Fetch(context.Context) (RawMessage, error)
	Commit(context.Context, RawMessage) error
}

type RawProducer interface {
	Publish(context.Context, RawMessage) error
}

type BatchProcessor interface {
	Process(context.Context, RawMessage) error
}

type RarityReader interface {
	Rarity(context.Context, tenant.ID) (identity.RarityBaseline, error)
}

type HistorySnapshot struct {
	Events  [][]byte
	Signals [][]byte
}

type HistoryReader interface {
	ReadDocuments(context.Context, string, map[string]string, time.Time, time.Time) (HistorySnapshot, error)
}

type SearchDocument struct {
	Index string
	ID    string
	Body  []byte
}

type DocumentProjector interface {
	BulkIndex(context.Context, []SearchDocument) error
}

type PermanentError struct {
	Err     error
	Message *RawMessage
}

func (err PermanentError) Error() string { return err.Err.Error() }
func (err PermanentError) Unwrap() error { return err.Err }
