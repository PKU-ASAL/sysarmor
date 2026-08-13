package policy

import (
	"sort"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func resolveRolloutPolicy(tenantID tenant.ID, agentID string, assignments []domainpolicy.Assignment, policies []domainpolicy.Policy) domainpolicy.Policy {
	published := publishedPolicies(tenantID, policies)
	candidates := rolloutCandidates(tenantID, agentID, assignments)
	for _, assignment := range candidates {
		if value, ok := published[policyKey{assignment.PolicyID, assignment.PolicyVersion}]; ok {
			return value
		}
	}
	if value, ok := latestDefaultPolicy(published); ok {
		return value
	}
	return domainpolicy.ManagerDefault(tenantID)
}

type policyKey struct {
	id      domainpolicy.ID
	version domainpolicy.Version
}

func publishedPolicies(tenantID tenant.ID, policies []domainpolicy.Policy) map[policyKey]domainpolicy.Policy {
	result := make(map[policyKey]domainpolicy.Policy, len(policies))
	for _, value := range policies {
		if value.TenantID == tenantID && value.Published {
			result[policyKey{value.ID, value.Version}] = value
		}
	}
	return result
}

func rolloutCandidates(tenantID tenant.ID, agentID string, assignments []domainpolicy.Assignment) []domainpolicy.Assignment {
	result := make([]domainpolicy.Assignment, 0, len(assignments))
	for _, value := range assignments {
		if value.TenantID == tenantID && rolloutAssignmentRank(value, agentID) >= 0 {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := rolloutAssignmentRank(result[i], agentID), rolloutAssignmentRank(result[j], agentID)
		if left != right {
			return left > right
		}
		if !result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			return result[i].UpdatedAt.After(result[j].UpdatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func rolloutAssignmentRank(value domainpolicy.Assignment, agentID string) int {
	if value.Target.AgentID != "" {
		if value.Target.AgentID == agentID {
			return 30
		}
		return -1
	}
	if value.Target.ScopeType == "" {
		return 10
	}
	return -1
}

func latestDefaultPolicy(policies map[policyKey]domainpolicy.Policy) (domainpolicy.Policy, bool) {
	var result domainpolicy.Policy
	var found bool
	for key, value := range policies {
		if key.id == domainpolicy.DefaultPolicyID && (!found || value.Version > result.Version) {
			result, found = value, true
		}
	}
	return result, found
}
