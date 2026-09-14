package sqlite

import (
	"testing"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func TestBeforeEventCursorKeepsSignalOnlyBatches(t *testing.T) {
	if beforeEventCursor(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{SignalSeqEnd: 3}}, 100) {
		t.Fatal("signal-only batch filtered by event cursor")
	}
	if !beforeEventCursor(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{EventCount: 1, EventSeqEnd: 99}}, 100) {
		t.Fatal("old event batch was not filtered")
	}
	if beforeEventCursor(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{EventCount: 1, EventSeqEnd: 100}}, 100) {
		t.Fatal("event at cursor was filtered")
	}
}
