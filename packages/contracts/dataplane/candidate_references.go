package dataplane

import (
	"fmt"
	"strconv"
	"strings"

	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type CandidateRejection struct {
	SignalID      string
	EventSequence *uint64
}

type ViolationCode string

const (
	MissingCandidateSubject   ViolationCode = "missing_candidate_subject"
	AmbiguousCandidateSubject ViolationCode = "ambiguous_candidate_subject"
	MissingCurrentEvent       ViolationCode = "missing_current_candidate_event"
	CandidateSubjectMismatch  ViolationCode = "candidate_event_subject_mismatch"
)

type ReferenceViolation struct {
	Code     ViolationCode
	SignalID string
}

func (violation *ReferenceViolation) Error() string {
	return fmt.Sprintf("model candidate %q violates %s", violation.SignalID, violation.Code)
}

// ValidateCandidateReferences enforces only the strong reference from an
// endpoint Model Candidate to its triggering Event in the same DataBatch.
func ValidateCandidateReferences(batch *dataplanev1.DataBatch) error {
	events := batchEvents(batch)
	for _, frame := range batch.GetSignals() {
		signal := frame.GetSignal()
		if !isModelCandidate(signal) {
			continue
		}
		subject, count := candidateSubject(signal)
		if count != 1 || subject == "" {
			code := MissingCandidateSubject
			if count > 1 {
				code = AmbiguousCandidateSubject
			}
			return &ReferenceViolation{Code: code, SignalID: signal.GetId()}
		}
		matched, mismatched := matchCurrentEvent(signal.GetEventRefs(), subject, events)
		if mismatched {
			return &ReferenceViolation{Code: CandidateSubjectMismatch, SignalID: signal.GetId()}
		}
		if !matched {
			return &ReferenceViolation{Code: MissingCurrentEvent, SignalID: signal.GetId()}
		}
	}
	return nil
}

func CountModelCandidates(batch *dataplanev1.DataBatch) uint64 {
	var count uint64
	for _, frame := range batch.GetSignals() {
		if isModelCandidate(frame.GetSignal()) {
			count++
		}
	}
	return count
}

func ModelCandidateRejections(batch *dataplanev1.DataBatch) []CandidateRejection {
	result := make([]CandidateRejection, 0)
	agentID := strings.TrimSpace(batch.GetHeader().GetAgentId())
	for _, frame := range batch.GetSignals() {
		signal := frame.GetSignal()
		if !isModelCandidate(signal) {
			continue
		}
		result = append(result, CandidateRejection{
			SignalID:      strings.TrimSpace(signal.GetId()),
			EventSequence: candidateEventSequence(agentID, signal.GetEventRefs()),
		})
	}
	return result
}

func candidateEventSequence(agentID string, refs []string) *uint64 {
	prefix := agentID + "-"
	var latest uint64
	found := false
	for _, ref := range refs {
		value := strings.TrimSpace(ref)
		if agentID == "" || !strings.HasPrefix(value, prefix) {
			continue
		}
		sequence, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 64)
		if err == nil && (!found || sequence > latest) {
			latest, found = sequence, true
		}
	}
	if !found {
		return nil
	}
	return &latest
}

func batchEvents(batch *dataplanev1.DataBatch) map[string][]string {
	result := make(map[string][]string, len(batch.GetEvents()))
	for _, frame := range batch.GetEvents() {
		event := frame.GetEvent()
		if id := strings.TrimSpace(event.GetId()); id != "" {
			result[id] = append(result[id], strings.TrimSpace(event.GetSubjectProc().GetStableId()))
		}
	}
	return result
}

func isModelCandidate(signal *signalv1.Signal) bool {
	return signal != nil && signal.GetDetectorKind() == signalv1.DetectorKind_DETECTOR_KIND_MODEL &&
		signal.GetStage() == signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE
}

func candidateSubject(signal *signalv1.Signal) (string, int) {
	subject, count := "", 0
	for _, entity := range signal.GetEntities() {
		if entity.GetKind() == "process" && entity.GetRole() == "subject" {
			count++
			subject = strings.TrimSpace(entity.GetKey())
		}
	}
	return subject, count
}

func matchCurrentEvent(refs []string, subject string, events map[string][]string) (matched, mismatched bool) {
	for _, ref := range refs {
		for _, eventSubject := range events[strings.TrimSpace(ref)] {
			if eventSubject == subject {
				matched = true
			} else {
				mismatched = true
			}
		}
	}
	return matched, mismatched
}
