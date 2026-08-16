package kafka

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestBatchProcessorClassifiesMalformedPayload(t *testing.T) {
	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: []byte("{")})
	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestBatchProcessorClassifiesUnsupportedSchema(t *testing.T) {
	batch := validWorkerBatch()
	batch.SchemaVersion = "sysarmor.dataplane/v9"
	raw, _ := protojson.Marshal(batch)
	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})
	assertPermanentEnvelope(t, err, "unsupported_schema_version")
}

func TestBatchProcessorRejectsMissingIdentity(t *testing.T) {
	batch := validWorkerBatch()
	batch.Header.AgentId = ""
	raw, _ := protojson.Marshal(batch)
	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})
	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestBatchDecoderMapsWireFramesToDomain(t *testing.T) {
	batch := validWorkerBatch()
	batch.Events = []*dataplanev1.EventFrame{{ObservedAt: "2026-08-11T01:02:03Z", Event: &eventv1.CanonicalEvent{Id: "event-a", TenantId: "default", Labels: map[string]string{"scenario": "checkout", "policy_id": "policy-old", "policy_version": "3"}}}}
	batch.Signals = []*dataplanev1.SignalFrame{{Signal: &signalv1.Signal{
		Id: "signal-a", Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		Stage: signalv1.SignalStage_SIGNAL_STAGE_CANDIDATE, DetectorKind: signalv1.DetectorKind_DETECTOR_KIND_RULE,
		Labels: map[string]string{"policy_id": "policy-old", "policy_version": "3"},
	}}}
	raw, _ := protojson.Marshal(batch)

	decoded, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})

	if err != nil || decoded.TenantID != "default" || decoded.AgentID != "agent-a" || decoded.ID != "batch-a" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	if len(decoded.Events) != 1 || decoded.Events[0].Event.ID != "event-a" || len(decoded.Signals) != 1 || decoded.Signals[0].Signal.ID != "signal-a" {
		t.Fatalf("events=%+v signals=%+v", decoded.Events, decoded.Signals)
	}
	if decoded.Events[0].Policy.ID != "policy-old" || decoded.Events[0].Policy.Version != 3 {
		t.Fatalf("event policy = %+v", decoded.Events[0].Policy)
	}
}

func TestBatchDecoderRejectsInvalidPolicyVersion(t *testing.T) {
	batch := validWorkerBatch()
	batch.Events = []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{Id: "event-a", Labels: map[string]string{"policy_id": "policy-a", "policy_version": "invalid"}}}}
	raw, _ := protojson.Marshal(batch)

	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})

	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestBatchDecoderRejectsMissingPolicyIdentity(t *testing.T) {
	batch := validWorkerBatch()
	batch.Events = []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{Id: "event-a"}}}
	raw, _ := protojson.Marshal(batch)

	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})

	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestBatchDecoderRejectsEventTenantMismatch(t *testing.T) {
	batch := validWorkerBatch()
	batch.Events = []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{Id: "event-a", TenantId: "other"}}}
	raw, _ := protojson.Marshal(batch)

	_, err := NewBatchDecoder().Decode(ports.RawMessage{Topic: "raw", Value: raw})

	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestStabilizeBatchTimeUsesLatestEvent(t *testing.T) {
	batch := validWorkerBatch()
	batch.Events = []*dataplanev1.EventFrame{{Event: &eventv1.CanonicalEvent{OccurredAtNs: 200}}}
	stabilizeBatchTime(batch, time.Unix(0, 100))
	if batch.GetHeader().GetCreatedAtUnixNano() != 200 {
		t.Fatalf("created_at=%d", batch.GetHeader().GetCreatedAtUnixNano())
	}
}

func assertPermanentEnvelope(t *testing.T, err error, class string) {
	t.Helper()
	var permanent ports.PermanentError
	if !errors.As(err, &permanent) || permanent.Message == nil {
		t.Fatalf("error = %v", err)
	}
	var envelope struct {
		FailureClass string `json:"failure_class"`
	}
	if decodeErr := json.Unmarshal(permanent.Message.Value, &envelope); decodeErr != nil || envelope.FailureClass != class {
		t.Fatalf("envelope=%+v decodeErr=%v", envelope, decodeErr)
	}
}

func validWorkerBatch() *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{SchemaVersion: "sysarmor.dataplane/v1", Header: &dataplanev1.BatchHeader{TenantId: "default", AgentId: "agent-a", HostId: "host-a", BatchId: "batch-a"}}
}
