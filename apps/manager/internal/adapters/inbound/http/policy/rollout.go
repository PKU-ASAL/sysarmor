package policy

import (
	"net/http"

	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

func (handler *Handler) Rollouts(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	context, ok := handler.resolve(writer, request)
	if !ok {
		return
	}
	query := policyapp.RolloutQuery{AgentID: request.URL.Query().Get("agent_id"), Status: request.URL.Query().Get("status")}
	result, err := handler.options.Rollout.List(request.Context(), context, query)
	if err != nil {
		http.Error(writer, "read policy rollout state", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, rolloutDocuments(result))
}

func rolloutDocuments(values []policyapp.Rollout) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, rolloutDocument(value))
	}
	return result
}

func rolloutDocument(value policyapp.Rollout) map[string]any {
	result := map[string]any{"tenant_id": value.TenantID.String(), "agent_id": value.AgentID,
		"status": value.Status, "drift": value.Drift, "last_dispatch_at": value.LastDispatchAt,
		"last_ack_at": value.LastAckAt, "health_observed_at": value.HealthObservedAt}
	setRolloutPolicyFields(result, value)
	setRolloutCommandFields(result, value)
	return result
}

func setRolloutPolicyFields(result map[string]any, value policyapp.Rollout) {
	setOptionalString(result, "desired_policy_id", value.DesiredPolicyID)
	setOptionalUint(result, "desired_policy_version", value.DesiredPolicyVersion)
	setOptionalString(result, "applied_policy_id", value.AppliedPolicyID)
	setOptionalUint(result, "applied_policy_version", value.AppliedPolicyVersion)
	result["pending_policy"] = pendingPolicyDocument(value.PendingPolicy)
}

func setRolloutCommandFields(result map[string]any, value policyapp.Rollout) {
	setOptionalString(result, "command_id", value.CommandID)
	setOptionalString(result, "command_status", value.CommandStatus)
	if value.AttemptCount > 0 {
		result["attempt_count"] = value.AttemptCount
	}
	setOptionalString(result, "error", value.Error)
}

func pendingPolicyDocument(value domainidentity.PendingPolicy) map[string]any {
	result := map[string]any{}
	setOptionalString(result, "status", value.Status)
	setOptionalString(result, "source", value.Source)
	setOptionalString(result, "policy_id", value.ID)
	setOptionalUint(result, "version", value.Version)
	setOptionalString(result, "digest", value.Digest)
	return result
}

func setOptionalString(result map[string]any, key, value string) {
	if value != "" {
		result[key] = value
	}
}

func setOptionalUint(result map[string]any, key string, value uint64) {
	if value > 0 {
		result[key] = value
	}
}
