package control

import (
	"reflect"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

var controlTestTime = time.Date(2026, 8, 10, 8, 0, 0, 0, time.UTC)

func TestSentCommandAcknowledgementIsIdempotent(t *testing.T) {
	command := Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a",
		Status: CommandSent,
	}
	ack := Acknowledgement{Status: CommandApplied, Message: "applied"}

	first, err := command.Acknowledge(ack, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Acknowledge(ack, controlTestTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second acknowledgement changed command: first=%+v second=%+v", first, second)
	}
}

func TestAcknowledgementRejectsConflictingTerminalStatus(t *testing.T) {
	command := Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a",
		Status: CommandApplied, AckStatus: CommandApplied,
	}

	_, err := command.Acknowledge(Acknowledgement{Status: CommandFailed}, controlTestTime)
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v, want conflict", failure.KindOf(err))
	}
}

func TestAcknowledgementRejectsConflictingTerminalResult(t *testing.T) {
	command := Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: CommandApplied,
		AckStatus: CommandApplied, AckMessage: "applied", AckPolicyID: "policy-a",
		AckPolicyVer: 2, AckReport: "report-a",
	}

	_, err := command.Acknowledge(Acknowledgement{
		Status: CommandApplied, Message: "applied", PolicyID: "policy-a",
		PolicyVersion: 2, Report: "different-report",
	}, controlTestTime)
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v, want conflict", failure.KindOf(err))
	}
}

func TestRejectedAcknowledgementRecordsPublicError(t *testing.T) {
	command := Command{ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: CommandSent}

	result, err := command.Acknowledge(Acknowledgement{Status: CommandRejected, Message: "policy denied"}, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != "policy denied" {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestAcknowledgementPreservesUnknownNonEmptyStatus(t *testing.T) {
	command := Command{ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Status: CommandSent}

	result, err := command.Acknowledge(Acknowledgement{Status: "partially_applied"}, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "partially_applied" {
		t.Fatalf("status = %q", result.Status)
	}
}

func TestEvidenceCompletionRejectsIdentityMismatch(t *testing.T) {
	pullback := EvidencePullback{
		ID: "evidence-a", TenantID: "tenant-a", AgentID: "agent-a",
		Status: EvidencePending,
	}

	_, err := pullback.Complete(EvidenceResult{
		TenantID: "tenant-a", AgentID: "agent-b", OK: true,
	}, controlTestTime)
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v, want conflict", failure.KindOf(err))
	}
}

func TestEvidenceCompletionIsIdempotent(t *testing.T) {
	pullback := EvidencePullback{
		ID: "evidence-a", TenantID: "tenant-a", AgentID: "agent-a",
		Status: EvidencePending,
	}
	result := EvidenceResult{
		TenantID: "tenant-a", AgentID: "agent-a", OK: true, Message: "collected",
	}

	first, err := pullback.Complete(result, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Complete(result, controlTestTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second completion changed pullback: first=%+v second=%+v", first, second)
	}
}

func TestEvidenceCompletionRejectsConflictingEvidence(t *testing.T) {
	pullback := EvidencePullback{
		ID: "evidence-a", TenantID: "tenant-a", AgentID: "agent-a", Status: EvidencePending,
	}
	first, err := pullback.Complete(EvidenceResult{
		TenantID: "tenant-a", AgentID: "agent-a", OK: true, Message: "collected", Evidence: []byte("first"),
	}, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}

	_, err = first.Complete(EvidenceResult{
		TenantID: "tenant-a", AgentID: "agent-a", OK: true, Message: "collected", Evidence: []byte("second"),
	}, controlTestTime.Add(time.Minute))
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v, want conflict", failure.KindOf(err))
	}
}

func TestNewCommandRequiresSupportedTypeAndIdentity(t *testing.T) {
	tests := []Command{
		{ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a"},
		{ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Type: "unsupported"},
		{ID: "command-a", AgentID: "agent-a", Type: CommandTypeContentUpdate},
		{ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a", Type: CommandTypeContentUpdate},
	}
	for _, value := range tests {
		if _, err := NewCommand(value, controlTestTime); failure.KindOf(err) != failure.InvalidArgument {
			t.Fatalf("NewCommand(%+v) kind = %v", value, failure.KindOf(err))
		}
	}
}

func TestCommandLifecycleTransitions(t *testing.T) {
	command, err := NewCommand(Command{
		ID: "command-a", TenantID: "tenant-a", AgentID: "agent-a",
		Type: CommandTypeContentUpdate, Payload: []byte(`{"kind":"iocpack"}`),
	}, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	sent := command.MarkSent(controlTestTime.Add(time.Minute))
	if sent.Status != CommandSent || sent.AttemptCount != 1 || sent.SentAt.IsZero() {
		t.Fatalf("sent = %+v", sent)
	}
	canceled := sent.Cancel("operator", "bad rollout", controlTestTime.Add(2*time.Minute))
	if canceled.Status != CommandCanceled || canceled.Actor != "operator" || canceled.Error != "bad rollout" {
		t.Fatalf("canceled = %+v", canceled)
	}
	retried := canceled.Retry("operator", "retry rollout", controlTestTime.Add(3*time.Minute))
	if retried.Status != CommandPending || retried.Reason != "retry rollout" || retried.Error != "" {
		t.Fatalf("retried = %+v", retried)
	}
	expired := retried.Expire("ttl elapsed", controlTestTime.Add(4*time.Minute))
	if expired.Status != CommandExpired || expired.Error != "ttl elapsed" || expired.ExpiredAt.IsZero() {
		t.Fatalf("expired = %+v", expired)
	}
}

func TestNewEvidencePullbackCopiesLabels(t *testing.T) {
	labels := map[string]string{"process": "sshd"}
	value, err := NewEvidencePullback(EvidencePullback{
		ID: "evidence-a", TenantID: "tenant-a", AgentID: "agent-a", Labels: labels,
	}, controlTestTime)
	if err != nil {
		t.Fatal(err)
	}
	labels["process"] = "changed"
	if value.Status != EvidencePending || value.Labels["process"] != "sshd" {
		t.Fatalf("pullback = %+v", value)
	}
}
