package telemetry

type DeliveryOutcome uint8

const (
	DeliveryAccepted DeliveryOutcome = iota + 1
	DeliveryDuplicate
	DeliveryRetryable
	DeliveryRejected
)

type Batch struct {
	ID       string
	TenantID string
	AgentID  string
	Payload  []byte
}

type Position struct {
	SegmentID     uint64
	RecordOffset  int64
	BatchSequence uint64
	BatchID       string
}

type StoredBatch struct {
	Position Position
	Batch    Batch
}

func Before(position, checkpoint Position) bool {
	if position.SegmentID < checkpoint.SegmentID {
		return true
	}
	return position.SegmentID == checkpoint.SegmentID && position.RecordOffset < checkpoint.RecordOffset
}
