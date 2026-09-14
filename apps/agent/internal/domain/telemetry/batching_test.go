package telemetry

import "testing"

func TestDecideFlushUsesCountBeforeBytes(t *testing.T) {
	reason, flush := DecideFlush(Pending{Items: 2, Bytes: 128}, Limits{MaxItems: 2, MaxBytes: 128})
	if !flush || reason != FlushByCount {
		t.Fatalf("decision = %q/%t, want count/true", reason, flush)
	}
}

func TestDecideFlushUsesBytesWhenCountIsBelowLimit(t *testing.T) {
	reason, flush := DecideFlush(Pending{Items: 1, Bytes: 128}, Limits{MaxItems: 2, MaxBytes: 128})
	if !flush || reason != FlushByBytes {
		t.Fatalf("decision = %q/%t, want bytes/true", reason, flush)
	}
}

func TestDecideFlushKeepsPendingBelowLimits(t *testing.T) {
	reason, flush := DecideFlush(Pending{Items: 1, Bytes: 127}, Limits{MaxItems: 2, MaxBytes: 128})
	if flush || reason != "" {
		t.Fatalf("decision = %q/%t, want empty/false", reason, flush)
	}
}
