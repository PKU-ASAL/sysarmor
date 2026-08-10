package ports

import "context"

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

type PermanentError struct {
	Err     error
	Message *RawMessage
}

func (err PermanentError) Error() string { return err.Err.Error() }
func (err PermanentError) Unwrap() error { return err.Err }
