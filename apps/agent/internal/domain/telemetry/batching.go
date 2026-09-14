package telemetry

type FlushReason string

const (
	FlushByCount FlushReason = "count"
	FlushByBytes FlushReason = "bytes"
)

type Pending struct {
	Items int
	Bytes int
}

type Limits struct {
	MaxItems int
	MaxBytes int
}

func DecideFlush(pending Pending, limits Limits) (FlushReason, bool) {
	if pending.Items >= limits.MaxItems {
		return FlushByCount, true
	}
	if pending.Bytes >= limits.MaxBytes {
		return FlushByBytes, true
	}
	return "", false
}
