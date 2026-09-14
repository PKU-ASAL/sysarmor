package response

import "testing"

func TestApplyPolicyRequirementsCopiesApprovalContract(t *testing.T) {
	command := ApplyPolicyRequirements(Command{}, Policy{
		ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"operator"},
	})

	if !command.ApprovalRequired || command.ApprovalThreshold != 2 {
		t.Fatalf("command = %+v", command)
	}
	if len(command.ApprovalRoles) != 1 || command.ApprovalRoles[0] != "operator" {
		t.Fatalf("approval roles = %v", command.ApprovalRoles)
	}
}

func TestApprovalCountDeduplicatesActorsAndAllowsAdmin(t *testing.T) {
	command := Command{
		ApprovalRoles: []string{"operator"},
		Approvals: []Approval{
			{Actor: "alice", Role: "operator", Approved: true},
			{Actor: "alice", Role: "operator", Approved: true},
			{Actor: "bob", Role: "viewer", Approved: true},
			{Actor: "root", Role: "admin", Approved: true},
		},
	}

	if got := ApprovalCount(command); got != 2 {
		t.Fatalf("count = %d", got)
	}
}

func TestDefaultPolicyAllowsObserveOnlyCollection(t *testing.T) {
	policy := DefaultPolicy()

	if len(policy.AllowedActions) != 2 || policy.AllowedActions[0] != "collect" {
		t.Fatalf("actions = %v", policy.AllowedActions)
	}
	if len(policy.AllowedModes) != 1 || policy.AllowedModes[0] != ModeObserve {
		t.Fatalf("modes = %v", policy.AllowedModes)
	}
}
