package response

import "testing"

func TestAuthorizeModeAndDestructiveAction(t *testing.T) {
	tests := []struct {
		name    string
		command Command
		policy  Policy
		allowed bool
		reason  string
	}{
		{name: "default observe collect", command: Command{Action: "collect"}, allowed: true},
		{name: "default rejects enforce", command: Command{Action: "noop", Mode: ModeEnforce}, reason: "response mode is not allowed by policy"},
		{name: "destructive requires opt in", command: Command{Action: "kill"}, reason: "destructive response action requires explicit policy approval"},
		{
			name: "explicit destructive enforce", command: Command{Action: "quarantine", Mode: ModeEnforce},
			policy: Policy{AllowedActions: []string{"quarantine"}, AllowedModes: []Mode{ModeEnforce}, AllowDestructive: true}, allowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.command.TenantID, tt.command.AgentID = "tenant-a", "agent-a"
			tt.command.PolicyID, tt.command.PolicyVersion = "policy-a", 1
			tt.policy.ID, tt.policy.Version = "policy-a", 1
			decision := Authorize(tt.command, tt.policy, AuthorizationContext{TenantID: "tenant-a", AgentID: "agent-a"})
			if decision.Allowed != tt.allowed || decision.Reason != tt.reason {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}
}

func TestAuthorizeRequiresDistinctAllowedApprovers(t *testing.T) {
	command := Command{
		Action: "collect",
		Approvals: []Approval{
			{Actor: "alice", Role: "responder", Approved: true},
			{Actor: "alice", Role: "responder", Approved: true},
			{Actor: "bob", Role: "viewer", Approved: true},
			{Actor: "carol", Role: "responder", Approved: true},
		},
	}
	policy := Policy{
		AllowedActions: []string{"collect"}, AllowedModes: []Mode{ModeObserve},
		ApprovalRequired: true, ApprovalThreshold: 2, ApprovalRoles: []string{"responder"},
	}
	command.TenantID, command.AgentID, command.PolicyID, command.PolicyVersion = "tenant-a", "agent-a", "policy-a", 1
	policy.ID, policy.Version = "policy-a", 1
	if decision := Authorize(command, policy, AuthorizationContext{TenantID: "tenant-a", AgentID: "agent-a"}); !decision.Allowed {
		t.Fatalf("decision=%+v", decision)
	}
}

func TestAuthorizeScope(t *testing.T) {
	tests := []struct {
		name         string
		command      Scope
		runtime      Scope
		runtimeKnown bool
		allowed      bool
	}{
		{name: "empty scope", allowed: true},
		{name: "matching scope", command: Scope{Type: "container", Selector: "abc"}, runtime: Scope{Type: "container", Selector: "abc"}, runtimeKnown: true, allowed: true},
		{name: "missing runtime scope", command: Scope{Type: "container", Selector: "abc"}},
		{name: "mismatched scope", command: Scope{Type: "container", Selector: "wrong"}, runtime: Scope{Type: "container", Selector: "abc"}, runtimeKnown: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := Authorize(Command{
				TenantID: "tenant-a", AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 1,
				Action: "collect", Scope: tt.command,
			}, Policy{ID: "policy-a", Version: 1}, AuthorizationContext{
				TenantID: "tenant-a", AgentID: "agent-a", RuntimeScope: tt.runtime, ScopeKnown: tt.runtimeKnown,
			})
			if decision.Allowed != tt.allowed {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}
}
