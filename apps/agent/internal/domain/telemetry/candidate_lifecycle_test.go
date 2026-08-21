package telemetry

import "testing"

func TestCandidateLifecycleTracksDeliveryStagesAndFailureReasons(t *testing.T) {
	var lifecycle CandidateLifecycle
	lifecycle.RecordCreated(2)
	lifecycle.RecordSpooled(2)
	lifecycle.RecordGatewayAccepted(1)
	lifecycle.RecordGatewayDuplicateAck(1)
	lifecycle.RecordContractRejected(1)
	lifecycle.RecordGatewayRejected(1)

	got := lifecycle.Snapshot()
	if got.Created != 2 || got.Spooled != 2 || got.GatewayAccepted != 1 || got.GatewayDuplicateAck != 1 ||
		got.ContractRejected != 1 || got.GatewayRejected != 1 {
		t.Fatalf("candidate lifecycle = %+v", got)
	}
}
