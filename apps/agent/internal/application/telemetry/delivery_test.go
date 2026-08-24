package telemetry

import (
	"context"
	"errors"
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/telemetry"
)

func TestDeliveryCheckpointsOnlyCommittedBatches(t *testing.T) {
	spool := &spoolFake{batches: []domaintelemetry.StoredBatch{
		batch("a", 1, "tenant-a", "agent-a"), batch("b", 2, "tenant-a", "agent-a"),
	}}
	sender := &senderFake{outcomes: []domaintelemetry.DeliveryOutcome{
		domaintelemetry.DeliveryAccepted, domaintelemetry.DeliveryRetryable,
	}}
	service := NewDelivery(spool, sender)

	err := service.DeliverAvailable(t.Context(), DeliveryScope{TenantID: "tenant-a", AgentID: "agent-a"})
	if err == nil {
		t.Fatal("DeliverAvailable() error = nil, want retryable error")
	}
	if len(spool.saved) != 1 || spool.saved[0].BatchID != "a" {
		t.Fatalf("saved checkpoints = %+v, want only a", spool.saved)
	}
}

func TestDeliveryRecordsCandidateGatewayOutcomes(t *testing.T) {
	lifecycle := &domaintelemetry.CandidateLifecycle{}
	spool := &spoolFake{batches: []domaintelemetry.StoredBatch{
		batch("accepted", 1, "tenant-a", "agent-a"), batch("rejected", 2, "tenant-a", "agent-a"),
	}}
	spool.batches[0].Batch.ModelCandidates = 2
	spool.batches[1].Batch.ModelCandidates = 1
	sender := &senderFake{outcomes: []domaintelemetry.DeliveryOutcome{
		domaintelemetry.DeliveryAccepted, domaintelemetry.DeliveryRejected,
	}}

	if err := NewDelivery(spool, sender, lifecycle).DeliverAvailable(t.Context(), DeliveryScope{TenantID: "tenant-a", AgentID: "agent-a"}); err == nil {
		t.Fatal("rejected Gateway batch did not fail delivery")
	}

	got := lifecycle.Snapshot()
	if got.GatewayAccepted != 2 || got.GatewayRejected != 1 {
		t.Fatalf("candidate lifecycle = %+v", got)
	}
}

func TestDeliveryCheckpointsDuplicateBatch(t *testing.T) {
	spool := &spoolFake{batches: []domaintelemetry.StoredBatch{batch("a", 1, "tenant-a", "agent-a")}}
	spool.batches[0].Batch.ModelCandidates = 2
	sender := &senderFake{outcomes: []domaintelemetry.DeliveryOutcome{domaintelemetry.DeliveryDuplicate}}
	lifecycle := &domaintelemetry.CandidateLifecycle{}

	if err := NewDelivery(spool, sender, lifecycle).DeliverAvailable(t.Context(), DeliveryScope{TenantID: "tenant-a", AgentID: "agent-a"}); err != nil {
		t.Fatal(err)
	}
	if len(spool.saved) != 1 || spool.saved[0].BatchID != "a" {
		t.Fatalf("saved checkpoints = %+v", spool.saved)
	}
	if got := lifecycle.Snapshot(); got.GatewayAccepted != 0 || got.GatewayDuplicateAck != 2 {
		t.Fatalf("candidate lifecycle = %+v, want duplicate separate from accepted", got)
	}
}

func TestDeliveryRejectsForeignEnrollmentEpochWithoutAdvancingCheckpoint(t *testing.T) {
	spool := &spoolFake{batches: []domaintelemetry.StoredBatch{
		batch("local", 1, "local", "device-a"), batch("managed", 2, "tenant-a", "agent-a"),
	}}
	spool.batches[0].Batch.EnrollmentEpoch = "standalone"
	spool.batches[1].Batch.EnrollmentEpoch = "enroll-a"
	sender := &senderFake{outcomes: []domaintelemetry.DeliveryOutcome{domaintelemetry.DeliveryAccepted}}

	if err := NewDelivery(spool, sender).DeliverAvailable(t.Context(), DeliveryScope{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentEpoch: "enroll-a"}); err == nil {
		t.Fatal("foreign enrollment epoch was silently skipped")
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %v", sender.sent)
	}
	if len(spool.saved) != 0 {
		t.Fatalf("saved checkpoints = %+v", spool.saved)
	}
}

func TestDeliveryDoesNotCheckpointSendError(t *testing.T) {
	spool := &spoolFake{batches: []domaintelemetry.StoredBatch{batch("a", 1, "tenant-a", "agent-a")}}
	sender := &senderFake{err: errors.New("offline")}

	if err := NewDelivery(spool, sender).DeliverAvailable(context.Background(), DeliveryScope{TenantID: "tenant-a", AgentID: "agent-a"}); !errors.Is(err, sender.err) {
		t.Fatalf("DeliverAvailable() error = %v", err)
	}
	if len(spool.saved) != 0 {
		t.Fatalf("saved checkpoints = %+v", spool.saved)
	}
}

func TestDeliveryRunStopsBeforeReadingCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	spool := &spoolFake{}
	done := make(chan struct{})
	go func() {
		NewDelivery(spool, &senderFake{}).Run(ctx, DeliveryScope{})
		close(done)
	}()
	<-done
	if spool.reads != 0 {
		t.Fatalf("spool reads = %d, want 0", spool.reads)
	}
}

type spoolFake struct {
	batches []domaintelemetry.StoredBatch
	saved   []domaintelemetry.Position
	from    uint64
	reads   int
}

func (s *spoolFake) Checkpoint(context.Context) (domaintelemetry.Position, error) {
	return domaintelemetry.Position{}, nil
}

func (s *spoolFake) Read(_ context.Context, from uint64, _ int) ([]domaintelemetry.StoredBatch, error) {
	s.from = from
	s.reads++
	return s.batches, nil
}

func (s *spoolFake) SaveCheckpoint(_ context.Context, position domaintelemetry.Position) error {
	s.saved = append(s.saved, position)
	return nil
}

type senderFake struct {
	outcomes []domaintelemetry.DeliveryOutcome
	sent     []string
	err      error
}

func (s *senderFake) Send(_ context.Context, batch domaintelemetry.Batch) (domaintelemetry.DeliveryOutcome, error) {
	s.sent = append(s.sent, batch.ID)
	if s.err != nil {
		return 0, s.err
	}
	if len(s.outcomes) == 0 {
		return domaintelemetry.DeliveryAccepted, nil
	}
	outcome := s.outcomes[0]
	s.outcomes = s.outcomes[1:]
	return outcome, nil
}

func batch(id string, sequence uint64, tenantID, agentID string) domaintelemetry.StoredBatch {
	return domaintelemetry.StoredBatch{
		Position: domaintelemetry.Position{SegmentID: 1, RecordOffset: int64(sequence), BatchSequence: sequence, BatchID: id},
		Batch:    domaintelemetry.Batch{ID: id, TenantID: tenantID, AgentID: agentID, Payload: []byte(id)},
	}
}
