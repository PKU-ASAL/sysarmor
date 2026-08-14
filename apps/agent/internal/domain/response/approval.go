package response

import "strings"

func DefaultPolicy() Policy {
	return Policy{
		AllowedActions: []string{"collect", "noop"},
		AllowedModes:   []Mode{ModeObserve},
	}
}

func ApplyPolicyRequirements(command Command, policy Policy) Command {
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

func ApprovalThreshold(command Command) uint32 {
	if command.ApprovalThreshold == 0 {
		return 1
	}
	return command.ApprovalThreshold
}

func ApprovalRoleAllowed(command Command, role string) bool {
	return approvalRoleAllowed(command.ApprovalRoles, role)
}

func ApprovalCount(command Command) uint32 {
	return approvalCount(command.Approvals, command.ApprovalRoles)
}

func approvalCount(approvals []Approval, roles []string) uint32 {
	seen := make(map[string]struct{}, len(approvals))
	for _, approval := range approvals {
		actor := strings.TrimSpace(approval.Actor)
		if !approval.Approved || actor == "" || !approvalRoleAllowed(roles, approval.Role) {
			continue
		}
		seen[actor] = struct{}{}
	}
	return uint32(len(seen))
}

func approvalRoleAllowed(roles []string, role string) bool {
	if len(roles) == 0 {
		return true
	}
	role = strings.TrimSpace(role)
	return role == "admin" || contains(roles, role)
}
