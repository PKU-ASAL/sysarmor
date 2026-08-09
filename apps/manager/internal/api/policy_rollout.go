package managerapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

type PolicyRollout struct {
	TenantID         string                          `json:"tenant_id"`
	AgentID          string                          `json:"agent_id"`
	Status           string                          `json:"status"`
	DesiredPolicyID  string                          `json:"desired_policy_id,omitempty"`
	DesiredPolicyVer uint64                          `json:"desired_policy_version,omitempty"`
	AppliedPolicyID  string                          `json:"applied_policy_id,omitempty"`
	AppliedPolicyVer uint64                          `json:"applied_policy_version,omitempty"`
	PendingPolicy    agenthealth.PendingPolicyStatus `json:"pending_policy,omitempty"`
	CommandID        string                          `json:"command_id,omitempty"`
	CommandStatus    string                          `json:"command_status,omitempty"`
	LastDispatchAt   time.Time                       `json:"last_dispatch_at,omitempty"`
	LastAckAt        time.Time                       `json:"last_ack_at,omitempty"`
	AttemptCount     uint32                          `json:"attempt_count,omitempty"`
	Error            string                          `json:"error,omitempty"`
	Drift            bool                            `json:"drift"`
	HealthObservedAt time.Time                       `json:"health_observed_at,omitempty"`
}

type rolloutTarget struct {
	tenantID string
	agentID  string
}

func (s *Server) policyRollouts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	tenantID, agentID, status := q.Get("tenant_id"), q.Get("agent_id"), q.Get("status")
	out := make([]PolicyRollout, 0)
	targets, err := s.policyRolloutTargets(r, tenantID, agentID)
	if err != nil {
		http.Error(w, "read policy rollout state", http.StatusInternalServerError)
		return
	}
	for _, target := range targets {
		rollout, err := s.policyRollout(r, target.tenantID, target.agentID)
		if err != nil {
			http.Error(w, "read policy rollout state", http.StatusInternalServerError)
			return
		}
		if status == "" || rollout.Status == status {
			out = append(out, rollout)
		}
	}
	writeJSON(w, out)
}

func (s *Server) policyRolloutTargets(r *http.Request, tenantID, agentID string) ([]rolloutTarget, error) {
	seen := make(map[rolloutTarget]struct{})
	request, err := s.identityRequest(r)
	if err != nil {
		return nil, err
	}
	result, err := s.identityQuery.ListAgents(r.Context(), request, identityapp.ListAgentsQuery{})
	if err != nil {
		return nil, err
	}
	for _, agent := range result.Agents {
		addRolloutTarget(seen, rolloutTarget{agent.Agent.TenantID.String(), string(agent.Agent.ID)}, tenantID, agentID)
	}
	assignments, err := s.store.ListAssignmentsWithError(tenantID, agentID)
	if err != nil {
		return nil, err
	}
	for _, assignment := range assignments {
		addRolloutTarget(seen, rolloutTarget{assignment.TenantID, assignment.AgentID}, tenantID, agentID)
	}
	out := make([]rolloutTarget, 0, len(seen))
	for target := range seen {
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].tenantID == out[j].tenantID {
			return out[i].agentID < out[j].agentID
		}
		return out[i].tenantID < out[j].tenantID
	})
	return out, nil
}

func addRolloutTarget(seen map[rolloutTarget]struct{}, target rolloutTarget, tenantID, agentID string) {
	if target.agentID == "" || tenantID != "" && target.tenantID != tenantID || agentID != "" && target.agentID != agentID {
		return
	}
	seen[target] = struct{}{}
}

func (s *Server) policyRollout(r *http.Request, tenantID, agentID string) (PolicyRollout, error) {
	rollout := PolicyRollout{TenantID: tenantID, AgentID: agentID, Status: "unknown"}
	desired, ok, err := s.store.EffectivePolicyWithError(tenantID, agentID, "", "")
	if err != nil {
		return PolicyRollout{}, err
	}
	if ok {
		rollout.DesiredPolicyID, rollout.DesiredPolicyVer = desired.PolicyID, desired.Version
	}
	request, err := s.identityRequest(r)
	if err != nil {
		return PolicyRollout{}, err
	}
	healthValue, healthErr := s.identityQuery.GetHealth(r.Context(), request, domainidentity.AgentID(agentID))
	hasHealth := healthErr == nil
	if healthErr != nil && failure.KindOf(healthErr) != failure.NotFound {
		return PolicyRollout{}, healthErr
	}
	if hasHealth {
		var health agenthealth.AgentHealth
		if err := json.Unmarshal(healthValue.Document, &health); err != nil {
			return PolicyRollout{}, err
		}
		rollout.AppliedPolicyID, rollout.AppliedPolicyVer = health.PolicyID, health.PolicyVersion
		rollout.PendingPolicy, rollout.HealthObservedAt = health.PendingPolicy, health.ObservedAt
	}
	commands, err := s.store.ListControlCommandsWithError(tenantID, agentID, controlmodel.ControlCommandTypePolicyUpdate)
	if err != nil {
		return PolicyRollout{}, err
	}
	command, hasCommand := latestPolicyCommand(commands, rollout.DesiredPolicyID, rollout.DesiredPolicyVer)
	if hasCommand {
		projectRolloutCommand(&rollout, command)
	}
	rollout.Drift = hasHealth && !samePolicy(rollout.DesiredPolicyID, rollout.DesiredPolicyVer, rollout.AppliedPolicyID, rollout.AppliedPolicyVer)
	rollout.Status = rolloutStatus(rollout, hasHealth, hasCommand)
	return rollout, nil
}

func latestPolicyCommand(commands []controlmodel.ControlCommand, policyID string, version uint64) (controlmodel.ControlCommand, bool) {
	var latest controlmodel.ControlCommand
	var found bool
	for _, command := range commands {
		if command.PolicyID != policyID || command.PolicyVersion != version {
			continue
		}
		if !found || command.CreatedAt.After(latest.CreatedAt) || command.CreatedAt.Equal(latest.CreatedAt) && command.UpdatedAt.After(latest.UpdatedAt) {
			latest, found = command, true
		}
	}
	return latest, found
}

func projectRolloutCommand(rollout *PolicyRollout, command controlmodel.ControlCommand) {
	rollout.CommandID, rollout.CommandStatus = command.CommandID, command.Status
	rollout.LastDispatchAt, rollout.LastAckAt = command.LastSentAt, command.AckedAt
	rollout.AttemptCount = command.AttemptCount
	rollout.Error = command.Error
	if rollout.Error == "" {
		rollout.Error = command.AckMessage
	}
}

func rolloutStatus(rollout PolicyRollout, hasHealth, hasCommand bool) string {
	if hasHealth && samePolicy(rollout.DesiredPolicyID, rollout.DesiredPolicyVer, rollout.AppliedPolicyID, rollout.AppliedPolicyVer) {
		return "applied"
	}
	if hasCommand && failedRolloutCommand(rollout.CommandStatus) {
		return "failed"
	}
	if samePolicy(rollout.DesiredPolicyID, rollout.DesiredPolicyVer, rollout.PendingPolicy.PolicyID, rollout.PendingPolicy.Version) || hasCommand && inFlightRolloutCommand(rollout.CommandStatus) {
		return "pending"
	}
	if rollout.Drift {
		return "drifted"
	}
	return "unknown"
}

func samePolicy(leftID string, leftVersion uint64, rightID string, rightVersion uint64) bool {
	return leftID != "" && leftID == rightID && leftVersion == rightVersion
}

func failedRolloutCommand(status string) bool {
	return status == controlmodel.ControlCommandStatusRejected || status == controlmodel.ControlCommandStatusFailed || status == controlmodel.ControlCommandStatusExpired
}

func inFlightRolloutCommand(status string) bool {
	return status == controlmodel.ControlCommandStatusPending || status == controlmodel.ControlCommandStatusSent
}
