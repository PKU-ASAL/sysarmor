package event

import "testing"

func TestStableProcessIDIsDeterministic(t *testing.T) {
	first := StableProcessID("host-a", 42, 100)
	second := StableProcessID("host-a", 42, 100)
	if first == "" || first != second {
		t.Fatalf("stable process IDs = %q, %q", first, second)
	}
	if first == StableProcessID("host-a", 42, 101) {
		t.Fatal("stable process ID ignores process start time")
	}
}

func TestEventIDSortsBySequence(t *testing.T) {
	if first, second := EventID("agent-a", 9), EventID("agent-a", 10); first >= second {
		t.Fatalf("event IDs are not sequence ordered: %q >= %q", first, second)
	}
}
