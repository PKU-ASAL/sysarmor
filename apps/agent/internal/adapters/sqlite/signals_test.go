package sqlite

import (
	"fmt"
	"testing"
	"time"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestSignalsRoundTripAndFilter(t *testing.T) {
	store := openStore(t, t.TempDir())
	defer store.Close()
	frames := []*dataplanev1.SignalFrame{
		signalFrame(1, "2026-07-13T00:00:01Z", "s1", "r1", "high"),
		signalFrame(2, "2026-07-13T00:00:02Z", "s2", "r2", "low"),
		signalFrame(3, "2026-07-13T00:00:03Z", "s3", "r1", "high"),
	}
	if err := store.AppendSignals(t.Context(), frames); err != nil {
		t.Fatal(err)
	}
	got, err := store.QuerySignals(t.Context(), SignalQuery{RuleID: "r1", Severity: "high", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GetSequence() != 3 || got[1].GetSequence() != 1 || got[0].GetSignal().GetId() != "s3" {
		t.Fatalf("signals=%+v", got)
	}
}

func TestSignalPruningKeepsNewestRows(t *testing.T) {
	store, err := Open(t.Context(), Options{RootDir: t.TempDir(), SignalMaxCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for sequence := uint64(1); sequence <= 3; sequence++ {
		if err := store.AppendSignals(t.Context(), []*dataplanev1.SignalFrame{signalFrame(sequence, time.Unix(int64(sequence), 0).UTC().Format(time.RFC3339), fmt.Sprintf("s%d", sequence), "r", "low")}); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := store.PruneSignals(t.Context())
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	got, err := store.QuerySignals(t.Context(), SignalQuery{Limit: 10})
	if err != nil || len(got) != 2 || got[1].GetSequence() != 2 {
		t.Fatalf("signals=%+v err=%v", got, err)
	}
}

func signalFrame(sequence uint64, observedAt, id, ruleID, severity string) *dataplanev1.SignalFrame {
	return &dataplanev1.SignalFrame{Sequence: sequence, ObservedAt: observedAt, Signal: &signalv1.Signal{Id: id, RuleId: ruleID, Severity: severity}}
}
