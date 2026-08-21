package worker

import (
	"context"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestInsertCorrelatedSignalsIsIdempotentBySignalID(t *testing.T) {
	db := newTelemetryDB(t)
	value := ports.SignalProcessingBatch{
		TenantID: "tenant-a", AgentID: "agent-a", BatchID: "batch-a", ClaimToken: "claim-a",
		Signals: []ports.SignalProcessingRecord{{
			SignalID: "signal-a", SubjectID: "process-a", TriggerEventID: "event-a", EventSequence: 7,
		}},
	}

	for attempt, want := range []uint64{1, 0} {
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		inserted, err := insertCorrelatedSignals(context.Background(), tx, value)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if inserted != want {
			t.Fatalf("attempt %d inserted=%d, want %d", attempt+1, inserted, want)
		}
	}

	var status, agentID, subjectID, eventID string
	var sequence uint64
	err := db.QueryRow(`SELECT status,agent_id,subject_id,trigger_event_id,event_sequence FROM worker_signal_processing WHERE tenant_id=? AND signal_id=?`, "tenant-a", "signal-a").Scan(&status, &agentID, &subjectID, &eventID, &sequence)
	if err != nil || status != "correlated" || agentID != "agent-a" || subjectID != "process-a" || eventID != "event-a" || sequence != 7 {
		t.Fatalf("status=%q agent=%q subject=%q event=%q sequence=%d err=%v", status, agentID, subjectID, eventID, sequence, err)
	}
}

func TestInsertRejectedSignalsIsIdempotentBySignalID(t *testing.T) {
	db := newTelemetryDB(t)
	value := ports.CandidateRejection{
		TenantID: "tenant-a", BatchID: "batch-a", FailureClass: "missing_current_candidate_event",
		Signals: []ports.RejectedSignal{{SignalID: "signal-a"}, {SignalID: "signal-b"}},
	}

	for attempt, want := range []uint64{2, 0} {
		tx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		inserted, err := insertRejectedSignals(context.Background(), tx, value)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if inserted != want {
			t.Fatalf("attempt %d inserted=%d, want %d", attempt+1, inserted, want)
		}
	}
}

func TestProjectSignalsAdvancesCorrelatedStateOnce(t *testing.T) {
	db := newTelemetryDB(t)
	value := ports.SignalProcessingBatch{
		TenantID: "tenant-a", AgentID: "agent-a", BatchID: "batch-a", ClaimToken: "claim-a",
		Signals: []ports.SignalProcessingRecord{{
			SignalID: "signal-a", SubjectID: "process-a", TriggerEventID: "event-a", EventSequence: 7,
		}},
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertCorrelatedSignals(context.Background(), tx, value); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	for attempt, want := range []uint64{1, 0} {
		tx, err = db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		projected, projectErr := projectSignals(context.Background(), tx, value.TenantID, value.BatchID, value.Signals)
		if projectErr != nil {
			_ = tx.Rollback()
			t.Fatal(projectErr)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if projected != want {
			t.Fatalf("attempt %d projected=%d, want %d", attempt+1, projected, want)
		}
	}
}
