package worker

import (
	"fmt"
	"strings"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func modelSignalProcessingRecords(batch ports.DataBatch) ([]ports.SignalProcessingRecord, error) {
	events := make(map[string]domaintelemetry.Event, len(batch.Events))
	for _, observed := range batch.Events {
		events[observed.Event.ID] = observed.Event
	}
	records := make([]ports.SignalProcessingRecord, 0)
	for _, observed := range batch.Signals {
		signal := observed.Signal
		if signal.Where != domaintelemetry.SignalWhereEndpoint || signal.DetectorKind != domaintelemetry.DetectorKindModel || signal.Stage != domaintelemetry.SignalStageCandidate {
			continue
		}
		record, err := modelSignalProcessingRecord(batch.ID, signal, events)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func modelSignalProcessingRecord(batchID string, signal domaintelemetry.Signal, events map[string]domaintelemetry.Event) (ports.SignalProcessingRecord, error) {
	subjectID, subjects := "", 0
	for _, entity := range signal.Entities {
		if entity.Kind == "process" && entity.Role == "subject" {
			subjectID, subjects = strings.TrimSpace(entity.Key), subjects+1
		}
	}
	if strings.TrimSpace(signal.ID) == "" || subjects != 1 || subjectID == "" {
		return ports.SignalProcessingRecord{}, fmt.Errorf("complete Model Candidate Signal identity is required")
	}
	for _, ref := range signal.EventRefs {
		event, ok := events[ref]
		if ok && event.SubjectProcess != nil && event.SubjectProcess.StableID == subjectID {
			return ports.SignalProcessingRecord{
				SignalID: signal.ID, SubjectID: subjectID, TriggerEventID: event.ID, EventSequence: event.Sequence,
			}, nil
		}
	}
	return ports.SignalProcessingRecord{}, fmt.Errorf("Model Candidate Signal %q has no current triggering Event in batch %q", signal.ID, batchID)
}
