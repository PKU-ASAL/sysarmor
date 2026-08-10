package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestBatchProcessorClassifiesMalformedPayload(t *testing.T) {
	err := (batchProcessor{processor: ingestworker.NewProcessor(&store.Store{}, nil)}).Process(context.Background(), ports.RawMessage{Topic: "raw", Value: []byte("{")})
	assertPermanentEnvelope(t, err, "invalid_data_batch")
}

func TestBatchProcessorClassifiesUnsupportedSchema(t *testing.T) {
	batch := validWorkerBatch()
	batch.SchemaVersion = "sysarmor.dataplane/v9"
	raw, _ := protojson.Marshal(batch)
	err := (batchProcessor{processor: ingestworker.NewProcessor(&store.Store{}, nil)}).Process(context.Background(), ports.RawMessage{Topic: "raw", Value: raw})
	assertPermanentEnvelope(t, err, "unsupported_schema_version")
}

func TestBatchProcessorRejectsMissingIdentity(t *testing.T) {
	batch := validWorkerBatch()
	batch.Header.AgentId = ""
	raw, _ := protojson.Marshal(batch)
	err := (batchProcessor{processor: ingestworker.NewProcessor(&store.Store{}, nil)}).Process(context.Background(), ports.RawMessage{Topic: "raw", Value: raw})
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
