package telemetry

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/protobuf/proto"
)

func TestCloudSenderMapsAcknowledgmentOutcomes(t *testing.T) {
	tests := []struct {
		name string
		ack  *dataplanev1.DataAck
		want domaintelemetry.DeliveryOutcome
	}{
		{name: "accepted", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_ACCEPTED}, want: domaintelemetry.DeliveryAccepted},
		{name: "duplicate", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_DUPLICATE}, want: domaintelemetry.DeliveryDuplicate},
		{name: "retryable", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_RETRYABLE}, want: domaintelemetry.DeliveryRetryable},
		{name: "rejected", ack: &dataplanev1.DataAck{Status: dataplanev1.DataAck_STATUS_REJECTED}, want: domaintelemetry.DeliveryRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sender := NewCloudSender(&batchSenderFake{ack: test.ack})
			outcome, err := sender.Send(t.Context(), domaintelemetry.Batch{Payload: encodedBatch(t, "batch-a")})
			if err != nil {
				t.Fatal(err)
			}
			if outcome != test.want {
				t.Fatalf("outcome = %v, want %v", outcome, test.want)
			}
		})
	}
}

type batchSenderFake struct{ ack *dataplanev1.DataAck }

func (sender *batchSenderFake) SendBatch(*dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	return sender.ack, nil
}

func encodedBatch(t *testing.T, id string) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{BatchId: id}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
