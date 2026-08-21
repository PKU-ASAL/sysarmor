package dataplane

import (
	"testing"

	dataplanecontract "github.com/sysarmor/sysarmor-next-project/packages/contracts/dataplane"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestMapBatchRejectsModelCandidateWithoutCurrentTrigger(t *testing.T) {
	batch := gatewayCandidateBatch()
	batch.Signals[0].Signal.EventRefs = []string{"missing-event"}

	if _, err := mapBatch(batch); err == nil {
		t.Fatal("Gateway accepted Model Candidate without a current trigger Event")
	}
}

func TestRejectedAckExposesCandidateReferenceReasonCode(t *testing.T) {
	batch := gatewayCandidateBatch()
	violation := &dataplanecontract.ReferenceViolation{Code: dataplanecontract.MissingCurrentEvent, SignalID: "candidate-a"}
	ack := rejectedAck(batch, violation)
	if ack.GetReasonCode() != string(dataplanecontract.MissingCurrentEvent) {
		t.Fatalf("reason code = %q", ack.GetReasonCode())
	}
}

func gatewayCandidateBatch() *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{TenantId: "tenant-a", AgentId: "agent-a", HostId: "host-a", BatchId: "batch-a"},
		Events: []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{
			Id: "event-a", SubjectProc: &eventv1.ProcessRef{StableId: "process-a"},
		}}},
		Signals: []*dataplanev1.SignalFrame{{Signal: &signalv1.Signal{
			Id: "candidate-a", Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE,
			DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_MODEL, EventRefs: []string{"event-a"},
			Entities: []*signalv1.EntityRef{{Kind: "process", Key: "process-a", Role: "subject"}},
		}}},
	}
}
