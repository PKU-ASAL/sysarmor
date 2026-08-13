package policy

import (
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func projectRollout(tenantID tenant.ID, agentID string, facts rolloutFacts) Rollout {
	result := Rollout{TenantID: tenantID, AgentID: agentID, Status: "unknown"}
	desired := resolveRolloutPolicy(tenantID, agentID, facts.assignments, facts.policies)
	result.DesiredPolicyID, result.DesiredPolicyVersion = desired.ID.String(), uint64(desired.Version)
	health, hasHealth := facts.healthByAgent[agentID]
	if hasHealth {
		result.AppliedPolicyID, result.AppliedPolicyVersion = health.AppliedPolicy.ID, health.AppliedPolicy.Version
		result.PendingPolicy, result.HealthObservedAt = health.PendingPolicy, health.ReportedAt
	}
	command, hasCommand := latestPolicyCommand(facts.commandsByAgent[agentID], result.DesiredPolicyID, result.DesiredPolicyVersion)
	if hasCommand {
		projectRolloutCommand(&result, command)
	}
	result.Drift = hasHealth && !samePolicy(result.DesiredPolicyID, result.DesiredPolicyVersion, result.AppliedPolicyID, result.AppliedPolicyVersion)
	result.Status = rolloutStatus(result, hasHealth, hasCommand)
	return result
}

func latestPolicyCommand(commands []domaincontrol.Command, policyID string, version uint64) (domaincontrol.Command, bool) {
	var latest domaincontrol.Command
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

func projectRolloutCommand(rollout *Rollout, command domaincontrol.Command) {
	rollout.CommandID, rollout.CommandStatus = command.ID, string(command.Status)
	rollout.LastDispatchAt, rollout.LastAckAt = command.LastSentAt, command.AckedAt
	rollout.AttemptCount, rollout.Error = command.AttemptCount, command.Error
	if rollout.Error == "" {
		rollout.Error = command.AckMessage
	}
}

func rolloutStatus(rollout Rollout, hasHealth, hasCommand bool) string {
	if hasHealth && samePolicy(rollout.DesiredPolicyID, rollout.DesiredPolicyVersion, rollout.AppliedPolicyID, rollout.AppliedPolicyVersion) {
		return "applied"
	}
	if hasCommand && failedRolloutCommand(rollout.CommandStatus) {
		return "failed"
	}
	if samePolicy(rollout.DesiredPolicyID, rollout.DesiredPolicyVersion, rollout.PendingPolicy.ID, rollout.PendingPolicy.Version) || hasCommand && inFlightRolloutCommand(rollout.CommandStatus) {
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
	return status == string(domaincontrol.CommandRejected) || status == string(domaincontrol.CommandFailed) || status == string(domaincontrol.CommandExpired)
}

func inFlightRolloutCommand(status string) bool {
	return status == string(domaincontrol.CommandPending) || status == string(domaincontrol.CommandSent)
}
