package response

import (
	"strings"
	"time"
)

type Policy struct {
	AllowedActions    []string
	AllowedModes      []string
	ApprovalRequired  bool
	ApprovalThreshold uint32
	ApprovalRoles     []string
	AllowDestructive  bool
}

type PrepareResult struct {
	Command Command
	Allowed bool
	Reason  string
}

func Prepare(value Command, policy Policy, runtime Scope, runtimeKnown bool, now time.Time) (PrepareResult, error) {
	value = applyPolicyRequirements(value, policy)
	command, err := NewCommand(value, now)
	if err != nil {
		return PrepareResult{}, err
	}
	if reason := scopeDenial(command.Scope, runtime, runtimeKnown); reason != "" {
		return denied(command, reason), nil
	}
	if reason := policyDenial(command, policy); reason != "" {
		return denied(command, reason), nil
	}
	return PrepareResult{Command: command, Allowed: true}, nil
}

func applyPolicyRequirements(command Command, policy Policy) Command {
	if !policy.ApprovalRequired {
		return command
	}
	command.ApprovalRequired = true
	if policy.ApprovalThreshold > 0 {
		command.ApprovalThreshold = policy.ApprovalThreshold
	}
	if len(policy.ApprovalRoles) > 0 {
		command.ApprovalRoles = append([]string(nil), policy.ApprovalRoles...)
	}
	return command
}

func scopeDenial(command, runtime Scope, known bool) string {
	command.Type, command.Selector = strings.TrimSpace(command.Type), strings.TrimSpace(command.Selector)
	runtime.Type, runtime.Selector = strings.TrimSpace(runtime.Type), strings.TrimSpace(runtime.Selector)
	if command.Type == "" && command.Selector == "" {
		return ""
	}
	if !known || runtime.Type == "" {
		return "agent runtime scope is required for scoped response command"
	}
	if command != runtime {
		return "response command scope does not match agent runtime scope"
	}
	return ""
}

func policyDenial(command Command, policy Policy) string {
	if !contains(policyModes(policy), command.Mode) {
		return "response mode is not allowed by policy"
	}
	if destructive(command.Action) && !policy.AllowDestructive {
		return "destructive response action requires explicit policy approval"
	}
	if !contains(policyActions(policy), command.Action) {
		return "response action is not allowed by policy"
	}
	return ""
}

func denied(command Command, reason string) PrepareResult {
	command.Status = StatusDenied
	command.ApprovalStatus = ""
	if command.Reason == "" {
		command.Reason = reason
	} else {
		command.Reason += "; denied: " + reason
	}
	return PrepareResult{Command: command, Reason: reason}
}

func policyModes(policy Policy) []string {
	if len(policy.AllowedModes) == 0 {
		return []string{"observe"}
	}
	return policy.AllowedModes
}

func policyActions(policy Policy) []string {
	if len(policy.AllowedActions) == 0 {
		return []string{"collect", "noop"}
	}
	return policy.AllowedActions
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func destructive(action string) bool {
	switch strings.TrimSpace(action) {
	case "kill", "block", "quarantine":
		return true
	default:
		return false
	}
}
