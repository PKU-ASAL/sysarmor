package telemetry

import "testing"

func TestCandidateLifecycleTracksDeliveryStagesAndFailureReasons(t *testing.T) {
	var lifecycle CandidateLifecycle
	lifecycle.RecordCreated(2)
	lifecycle.RecordSpooled(2)
	lifecycle.RecordGatewayAccepted(1)
	lifecycle.RecordDeliveryAttempted(2)
	lifecycle.RecordGatewayRetryable(1)
	lifecycle.RecordDeliveryError(1, "gateway unavailable")
	lifecycle.RecordGatewayDuplicateAck(1)
	lifecycle.RecordContractRejected(1)
	lifecycle.RecordGatewayRejected(1)

	got := lifecycle.Snapshot()
	if got.Created != 2 || got.Spooled != 2 || got.GatewayAccepted != 1 || got.GatewayDuplicateAck != 1 ||
		got.DeliveryAttempted != 2 || got.GatewayRetryable != 1 || got.DeliveryErrors != 1 || got.LastDeliveryError != "gateway unavailable" ||
		got.ContractRejected != 1 || got.GatewayRejected != 1 {
		t.Fatalf("candidate lifecycle = %+v", got)
	}
}
