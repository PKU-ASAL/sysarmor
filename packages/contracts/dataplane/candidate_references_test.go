package dataplane

import (
	"errors"
	"testing"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestValidateCandidateReferencesAcceptsCurrentTriggerAlongsideHistory(t *testing.T) {
	batch := candidateBatch("process-a", []string{"historical-event", "event-current"})

	if err := ValidateCandidateReferences(batch); err != nil {
		t.Fatalf("valid candidate references rejected: %v", err)
	}
	if got := CountModelCandidates(batch); got != 1 {
		t.Fatalf("model candidates = %d, want 1", got)
	}
}

func TestModelCandidateRejectionsExtractTriggerSequence(t *testing.T) {
	batch := candidateBatch("process-a", []string{"agent-a-00000000000000000007"})
	batch.Header = &dataplanev1.BatchHeader{AgentId: "agent-a"}

	got := ModelCandidateRejections(batch)

	if len(got) != 1 || got[0].SignalID != "candidate-a" || got[0].EventSequence == nil || *got[0].EventSequence != 7 {
		t.Fatalf("rejections = %+v", got)
	}
}

func TestModelCandidateRejectionsLeaveUntrustedSequenceUnknown(t *testing.T) {
	batch := candidateBatch("process-a", []string{"not-an-agent-event"})
	batch.Header = &dataplanev1.BatchHeader{AgentId: "agent-a"}

	got := ModelCandidateRejections(batch)

	if len(got) != 1 || got[0].EventSequence != nil {
		t.Fatalf("rejections = %+v", got)
	}
}

func TestValidateCandidateReferencesRejectsInvalidStrongReference(t *testing.T) {
	tests := []struct {
		name string
		edit func(*dataplanev1.DataBatch)
		code ViolationCode
	}{
		{
			name: "missing subject",
			edit: func(batch *dataplanev1.DataBatch) { batch.Signals[0].Signal.Entities = nil },
			code: MissingCandidateSubject,
		},
		{
			name: "empty subject",
			edit: func(batch *dataplanev1.DataBatch) { batch.Signals[0].Signal.Entities[0].Key = " " },
			code: MissingCandidateSubject,
		},
		{
			name: "multiple subjects",
			edit: func(batch *dataplanev1.DataBatch) {
				batch.Signals[0].Signal.Entities = append(batch.Signals[0].Signal.Entities,
					&signalv1.EntityRef{Kind: "process", Key: "process-b", Role: "subject"})
			},
			code: AmbiguousCandidateSubject,
		},
		{
			name: "empty duplicate subject",
			edit: func(batch *dataplanev1.DataBatch) {
				batch.Signals[0].Signal.Entities = append(batch.Signals[0].Signal.Entities,
					&signalv1.EntityRef{Kind: "process", Key: "", Role: "subject"})
			},
			code: AmbiguousCandidateSubject,
		},
		{
			name: "missing current event",
			edit: func(batch *dataplanev1.DataBatch) { batch.Signals[0].Signal.EventRefs = []string{"historical-event"} },
			code: MissingCurrentEvent,
		},
		{
			name: "subject mismatch",
			edit: func(batch *dataplanev1.DataBatch) { batch.Events[0].Event.SubjectProc.StableId = "process-b" },
			code: CandidateSubjectMismatch,
		},
		{
			name: "one of multiple current events has a different subject",
			edit: func(batch *dataplanev1.DataBatch) {
				batch.Events = append(batch.Events, &dataplanev1.EventFrame{Event: &eventv1.CanonicalEvent{
					Id: "event-other", SubjectProc: &eventv1.ProcessRef{StableId: "process-b"},
				}})
				batch.Signals[0].Signal.EventRefs = []string{"event-current", "event-other"}
			},
			code: CandidateSubjectMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := candidateBatch("process-a", []string{"event-current"})
			test.edit(batch)

			err := ValidateCandidateReferences(batch)
			var violation *ReferenceViolation
			if !errors.As(err, &violation) || violation.Code != test.code {
				t.Fatalf("error = %v, want reference violation %q", err, test.code)
			}
		})
	}
}

func candidateBatch(subject string, refs []string) *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{
		Events: []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{
			Id: "event-current", SubjectProc: &eventv1.ProcessRef{StableId: subject},
		}}},
		Signals: []*dataplanev1.SignalFrame{{Signal: &signalv1.Signal{
			Id: "candidate-a", DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_MODEL,
			Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, EventRefs: refs,
			Entities: []*signalv1.EntityRef{{Kind: "process", Key: subject, Role: "subject"}},
		}}},
	}
}
