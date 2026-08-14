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
	if len(command.ApprovalRoles) == 0 {
		return true
	}
	role = strings.TrimSpace(role)
	return role == "admin" || contains(command.ApprovalRoles, role)
}

func ApprovalCount(command Command) uint32 {
	seen := make(map[string]struct{}, len(command.Approvals))
	for _, approval := range command.Approvals {
		actor := strings.TrimSpace(approval.Actor)
		if !approval.Approved || actor == "" || !ApprovalRoleAllowed(command, approval.Role) {
			continue
		}
		seen[actor] = struct{}{}
	}
	return uint32(len(seen))
}
