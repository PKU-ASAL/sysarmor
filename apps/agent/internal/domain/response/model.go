package response

import (
	"fmt"
	"strings"
	"time"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

type Scope struct {
	Type     string
	Selector string
}

type Approval struct {
	Actor    string
	Role     string
	Approved bool
}

type Command struct {
	ID                string
	TenantID          string
	AgentID           string
	PolicyID          string
	PolicyVersion     uint64
	SignalID          string
	Labels            map[string]string
	Scope             Scope
	Action            string
	Mode              Mode
	Target            string
	Reason            string
	Status            string
	Actor             string
	ApprovalRequired  bool
	ApprovalStatus    string
	ApprovalThreshold uint32
	ApprovalRoles     []string
	Approvals         []Approval
}

type Policy struct {
	ID                string
	Version           uint64
	AllowedActions    []string
	AllowedModes      []Mode
	ApprovalRequired  bool
	ApprovalThreshold uint32
	ApprovalRoles     []string
	AllowDestructive  bool
}

type AuthorizationContext struct {
	TenantID     string
	AgentID      string
	RuntimeScope Scope
	ScopeKnown   bool
}

type Decision struct {
	Allowed bool
	Reason  string
}

type Ack struct {
	ResponseID  string
	TenantID    string
	AgentID     string
	Accepted    bool
	Unsupported bool
	ObserveOnly bool
	Executed    bool
	Message     string
	ObservedAt  time.Time
}

func Normalize(command Command) Command {
	command.Action = strings.TrimSpace(command.Action)
	if command.Action == "" {
		command.Action = "collect"
	}
	if command.Mode == "" {
		command.Mode = ModeObserve
	}
	return command
}

func Authorize(command Command, policy Policy, auth AuthorizationContext) Decision {
	command = Normalize(command)
	if decision := authorizeBinding(command, policy, auth); !decision.Allowed {
		return decision
	}
	if decision := authorizeModeAndAction(command, policy); !decision.Allowed {
		return decision
	}
	if decision := authorizeScope(command.Scope, auth.RuntimeScope, auth.ScopeKnown); !decision.Allowed {
		return decision
	}
	return authorizeApproval(command, policy)
}

func authorizeBinding(command Command, policy Policy, auth AuthorizationContext) Decision {
	if command.TenantID == "" || command.TenantID != auth.TenantID {
		return Decision{Reason: "response command tenant does not match agent identity"}
	}
	if command.AgentID == "" || command.AgentID != auth.AgentID {
		return Decision{Reason: "response command agent does not match agent identity"}
	}
	if command.PolicyID == "" || command.PolicyID != policy.ID {
		return Decision{Reason: "response command policy does not match active policy"}
	}
	if command.PolicyVersion == 0 || command.PolicyVersion != policy.Version {
		return Decision{Reason: "response command policy version does not match active policy"}
	}
	return Decision{Allowed: true}
}

func authorizeModeAndAction(command Command, policy Policy) Decision {
	modes := policy.AllowedModes
	if len(modes) == 0 {
		modes = []Mode{ModeObserve}
	}
	if !containsMode(modes, command.Mode) {
		return Decision{Reason: "response mode is not allowed by policy"}
	}
	if destructive(command.Action) && !policy.AllowDestructive {
		return Decision{Reason: "destructive response action requires explicit policy approval"}
	}
	actions := policy.AllowedActions
	if len(actions) == 0 {
		actions = []string{"collect", "noop"}
	}
	if !contains(actions, command.Action) {
		return Decision{Reason: "response action is not allowed by policy"}
	}
	return Decision{Allowed: true}
}

func authorizeScope(command, runtime Scope, runtimeKnown bool) Decision {
	command.Type, command.Selector = strings.TrimSpace(command.Type), strings.TrimSpace(command.Selector)
	if command.Type == "" && command.Selector == "" {
		return Decision{Allowed: true}
	}
	if !runtimeKnown || strings.TrimSpace(runtime.Type) == "" {
		return Decision{Reason: "agent runtime scope is required for scoped response command"}
	}
	if command.Type != strings.TrimSpace(runtime.Type) || command.Selector != strings.TrimSpace(runtime.Selector) {
		return Decision{Reason: "response command scope does not match agent runtime scope"}
	}
	return Decision{Allowed: true}
}

func authorizeApproval(command Command, policy Policy) Decision {
	if !policy.ApprovalRequired && !command.ApprovalRequired {
		return Decision{Allowed: true}
	}
	threshold := policy.ApprovalThreshold
	if threshold == 0 {
		threshold = command.ApprovalThreshold
	}
	if threshold == 0 {
		threshold = 1
	}
	roles := policy.ApprovalRoles
	if len(roles) == 0 {
		roles = command.ApprovalRoles
	}
	if approvalCount(command.Approvals, roles) < threshold {
		return Decision{Reason: fmt.Sprintf("response requires %d approved actor(s)", threshold)}
	}
	return Decision{Allowed: true}
}

func approvalCount(approvals []Approval, roles []string) uint32 {
	seen := map[string]struct{}{}
	for _, approval := range approvals {
		key := strings.TrimSpace(approval.Actor)
		if !approval.Approved || key == "" || (!contains(roles, approval.Role) && len(roles) > 0 && approval.Role != "admin") {
			continue
		}
		seen[key] = struct{}{}
	}
	return uint32(len(seen))
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func containsMode(values []Mode, want Mode) bool {
	for _, value := range values {
		if value == want {
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
