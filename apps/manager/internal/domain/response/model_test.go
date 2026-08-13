package response

import (
	"reflect"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

var responseTestTime = time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)

func TestApprovalCreatesPendingCommandOnlyAtThreshold(t *testing.T) {
	command, err := NewCommand(Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "collect",
		ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"admin"},
	}, responseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	first, err := command.Decide(Approval{Actor: "admin-a", Role: "admin", Approved: true}, responseTestTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusPendingApproval || first.ApprovalStatus != ApprovalPartial {
		t.Fatalf("first approval = %+v", first)
	}
	second, err := first.Decide(Approval{Actor: "admin-b", Role: "admin", Approved: true}, responseTestTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusPending || second.ApprovalStatus != ApprovalApproved || second.ApprovedBy != "admin-b" {
		t.Fatalf("second approval = %+v", second)
	}
}

func TestApprovalRejectsConflictingDecisionFromSameActor(t *testing.T) {
	command, err := NewCommand(Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "collect",
		ApprovalRequired: true, ApprovalThreshold: 2,
	}, responseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := command.Decide(Approval{Actor: "admin-a", Role: "admin", Approved: true}, responseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	_, err = approved.Decide(Approval{Actor: "admin-a", Role: "admin", Approved: false}, responseTestTime)
	if failure.KindOf(err) != failure.Conflict {
		t.Fatalf("kind = %v error=%v", failure.KindOf(err), err)
	}
}

func TestFinalApprovalDecisionIsIdempotent(t *testing.T) {
	tests := []struct {
		name     string
		approved bool
	}{
		{name: "approved", approved: true},
		{name: "rejected", approved: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := NewCommand(Command{
				ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", ApprovalRequired: true,
			}, responseTestTime)
			if err != nil {
				t.Fatal(err)
			}
			decision := Approval{Actor: "admin-a", Role: "admin", Approved: test.approved, Reason: "reviewed"}
			first, err := command.Decide(decision, responseTestTime.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			second, err := first.Decide(decision, responseTestTime.Add(2*time.Minute))
			if err != nil || !reflect.DeepEqual(second, first) {
				t.Fatalf("second=%+v first=%+v error=%v", second, first, err)
			}
		})
	}
}

func TestAcknowledgementIsIdempotentForCompleteResult(t *testing.T) {
	command := Command{ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Status: StatusPending}
	ack := Acknowledgement{TenantID: "tenant-a", AgentID: "agent-a", Accepted: true, Executed: true, Message: "done"}
	first, err := command.Acknowledge(ack, responseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.Command.Acknowledge(ack, responseTestTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("second acknowledgement changed result: first=%+v second=%+v", first, second)
	}
}

func TestCommandPolicyAndScopeDenialIsPersistable(t *testing.T) {
	result, err := Prepare(Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", Action: "kill", Mode: "enforce",
		Scope: Scope{Type: "container", Selector: "wrong"}, Reason: "contain",
	}, Policy{
		AllowedActions: []string{"kill"}, AllowedModes: []string{"enforce"}, AllowDestructive: true,
		ApprovalRequired: true,
	},
		Scope{Type: "container", Selector: "expected"}, true, responseTestTime)
	if err != nil {
		t.Fatal(err)
	}
	if result.Allowed || result.Command.Status != StatusDenied || result.Command.ApprovalStatus != "" ||
		result.Command.Reason != "contain; denied: response command scope does not match agent runtime scope" {
		t.Fatalf("prepare result = %+v", result)
	}
}
