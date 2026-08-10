package store

import (
	"fmt"
	"sort"
	"time"

	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func (s *Store) EnsureDefaultPolicy(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Rules) == 0 {
		s.Rules = policymodel.DefaultRules()
	}
	for i, policy := range s.Policies {
		if policy.TenantID == tenantID && policy.PolicyID == policymodel.DefaultPolicyID && policy.Version == policymodel.DefaultPolicyVersion {
			if !managerDefaultPolicyUsable(policy) {
				s.Policies[i] = policymodel.Normalize(policymodel.ManagerDefaultPolicy(tenantID))
			}
			return
		}
	}
	s.Policies = append(s.Policies, policymodel.Normalize(policymodel.ManagerDefaultPolicy(tenantID)))
}

func (s *Store) EnsureDefaultPolicyWithError(tenantID string) error {
	s.EnsureDefaultPolicy(tenantID)
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	backend, ctx := s.backendCtx()
	if backend == nil {
		return nil
	}
	existing, ok, err := backend.GetPolicy(ctxOrBackground(ctx), tenantID, policymodel.DefaultPolicyID, policymodel.DefaultPolicyVersion)
	if err != nil {
		return fmt.Errorf("read default policy: %w", err)
	}
	if ok && managerDefaultPolicyUsable(existing) {
		return nil
	}
	policy := policymodel.Normalize(policymodel.ManagerDefaultPolicy(tenantID))
	if err := backend.WritePolicy(ctxOrBackground(ctx), policy); err != nil {
		return fmt.Errorf("persist default policy: %w", err)
	}
	return nil
}

func managerDefaultPolicyUsable(policy policymodel.Policy) bool {
	if !policy.Published || policy.Detection == nil {
		return false
	}
	for _, ruleset := range policy.Detection.RuleSets {
		if ruleset.Ref == policymodel.DefaultRuleSetRef {
			return true
		}
	}
	return false
}

func (s *Store) UpsertRule(rule policymodel.RuleContent) {
	if rule.RuleID == "" {
		return
	}
	if rule.Version == 0 {
		rule.Version = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.Rules {
		if existing.RuleID == rule.RuleID && existing.Version == rule.Version {
			s.Rules[i] = rule
			return
		}
	}
	s.Rules = append(s.Rules, rule)
}

func (s *Store) ListRules(where string) []policymodel.RuleContent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policymodel.RuleContent, 0, len(s.Rules))
	for _, rule := range s.Rules {
		if where != "" && rule.Where != where {
			continue
		}
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Where == out[j].Where {
			if out[i].RuleID == out[j].RuleID {
				return out[i].Version < out[j].Version
			}
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Where < out[j].Where
	})
	return out
}

func (s *Store) UpsertPolicy(policy policymodel.Policy) policymodel.Policy {
	out, _ := s.UpsertPolicyWithError(policy)
	return out
}

func (s *Store) UpsertPolicyWithError(policy policymodel.Policy) (policymodel.Policy, error) {
	if policy.PolicyID == "" {
		return policymodel.Policy{}, nil
	}
	policy = policymodel.Normalize(policy)
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	s.mu.Lock()
	policies, policy := upsertPolicySnapshot(s.Policies, policy)
	backend, ctx := s.backend, s.baseCtx
	if backend == nil {
		oldPolicies := s.Policies
		s.Policies = policies
		if err := s.persistFileLocked(); err != nil {
			s.Policies = oldPolicies
			s.mu.Unlock()
			return policymodel.Policy{}, fmt.Errorf("write policy: %w", err)
		}
		s.mu.Unlock()
		return policy, nil
	}
	s.mu.Unlock()
	if err := backend.WritePolicy(ctxOrBackground(ctx), policy); err != nil {
		return policymodel.Policy{}, fmt.Errorf("write policy: %w", err)
	}
	s.mu.Lock()
	s.Policies = policies
	s.mu.Unlock()
	return policy, nil
}

func upsertPolicySnapshot(policies []policymodel.Policy, policy policymodel.Policy) ([]policymodel.Policy, policymodel.Policy) {
	out := append([]policymodel.Policy(nil), policies...)
	for i, existing := range out {
		if existing.TenantID == policy.TenantID && existing.PolicyID == policy.PolicyID && existing.Version == policy.Version {
			if !existing.CreatedAt.IsZero() {
				policy.CreatedAt = existing.CreatedAt
			}
			out[i] = policy
			return out, policy
		}
	}
	return append(out, policy), policy
}

func (s *Store) RecordPolicyAudit(record policymodel.AuditRecord) policymodel.AuditRecord {
	record = normalizePolicyAudit(record)
	s.mu.Lock()
	s.PolicyAudits = append(s.PolicyAudits, record)
	backend, ctx := s.backend, s.baseCtx
	s.mu.Unlock()
	if backend != nil {
		_ = backend.WritePolicyAudit(ctxOrBackground(ctx), record)
	}
	return record
}

func normalizePolicyAudit(record policymodel.AuditRecord) policymodel.AuditRecord {
	if record.TenantID == "" {
		record.TenantID = "default"
	}
	if record.Status == "" {
		record.Status = "ok"
	}
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	if record.AuditID == "" {
		record.AuditID = fmt.Sprintf("policy-audit-%d", now.UnixNano())
	}
	return record
}

func (s *Store) ListPolicyAudits(tenantID, policyID string) []policymodel.AuditRecord {
	if backend, ctx := s.backendCtx(); backend != nil {
		if audits, err := backend.ListPolicyAudits(ctx, tenantID, policyID); err == nil {
			return audits
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policymodel.AuditRecord, 0, len(s.PolicyAudits))
	for _, record := range s.PolicyAudits {
		if tenantID != "" && record.TenantID != tenantID {
			continue
		}
		if policyID != "" && record.PolicyID != policyID {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (s *Store) ListPolicyAuditsWithError(tenantID, policyID string) ([]policymodel.AuditRecord, error) {
	if backend, ctx := s.backendCtx(); backend != nil {
		audits, err := backend.ListPolicyAudits(ctx, tenantID, policyID)
		if err != nil {
			return nil, fmt.Errorf("list policy audits: %w", err)
		}
		return audits, nil
	}
	return s.ListPolicyAudits(tenantID, policyID), nil
}

func (s *Store) ListPolicies(tenantID string) []policymodel.Policy {
	if backend, ctx := s.backendCtx(); backend != nil {
		if policies, err := backend.ListPolicies(ctx, tenantID); err == nil {
			return policies
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policymodel.Policy, 0, len(s.Policies))
	for _, policy := range s.Policies {
		if tenantID != "" && policy.TenantID != tenantID {
			continue
		}
		out = append(out, policy)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			if out[i].PolicyID == out[j].PolicyID {
				return out[i].Version < out[j].Version
			}
			return out[i].PolicyID < out[j].PolicyID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func (s *Store) ListPoliciesWithError(tenantID string) ([]policymodel.Policy, error) {
	if backend, ctx := s.backendCtx(); backend != nil {
		policies, err := backend.ListPolicies(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		return policies, nil
	}
	return s.ListPolicies(tenantID), nil
}

func (s *Store) GetPolicy(tenantID, policyID string, version uint64) (policymodel.Policy, bool) {
	if backend, ctx := s.backendCtx(); backend != nil {
		if policy, ok, err := backend.GetPolicy(ctx, tenantID, policyID, version); err == nil && ok {
			return policy, true
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest policymodel.Policy
	var ok bool
	for _, policy := range s.Policies {
		if tenantID != "" && policy.TenantID != tenantID {
			continue
		}
		if policy.PolicyID != policyID {
			continue
		}
		if version != 0 && policy.Version != version {
			continue
		}
		if version != 0 {
			return policy, true
		}
		if !ok || policy.Version > latest.Version {
			latest = policy
			ok = true
		}
	}
	return latest, ok
}

func (s *Store) GetPolicyWithError(tenantID, policyID string, version uint64) (policymodel.Policy, bool, error) {
	if backend, ctx := s.backendCtx(); backend != nil {
		policy, ok, err := backend.GetPolicy(ctx, tenantID, policyID, version)
		if err != nil {
			return policymodel.Policy{}, false, fmt.Errorf("get policy: %w", err)
		}
		return policy, ok, nil
	}
	policy, ok := s.GetPolicy(tenantID, policyID, version)
	return policy, ok, nil
}

func (s *Store) PublishPolicy(tenantID, policyID string, version uint64, published bool) (policymodel.Policy, bool, error) {
	if tenantID == "" {
		tenantID = "default"
	}
	if policyID == "" {
		return policymodel.Policy{}, false, nil
	}
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if err := s.loadPolicyForCommit(tenantID, policyID, version); err != nil {
		return policymodel.Policy{}, false, err
	}
	s.mu.RLock()
	index := policyIndex(s.Policies, tenantID, policyID, version)
	if index < 0 {
		s.mu.RUnlock()
		return policymodel.Policy{}, false, nil
	}
	policy := s.Policies[index]
	backend, ctx := s.backend, s.baseCtx
	s.mu.RUnlock()
	policy.Published, policy.UpdatedAt = published, time.Now().UTC()
	if backend != nil {
		if err := backend.WritePolicy(ctxOrBackground(ctx), policy); err != nil {
			return policymodel.Policy{}, false, fmt.Errorf("write policy publication: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldPolicies := s.Policies
	s.Policies, _ = upsertPolicySnapshot(s.Policies, policy)
	if err := s.persistFileLocked(); err != nil {
		s.Policies = oldPolicies
		return policymodel.Policy{}, false, fmt.Errorf("write policy publication: %w", err)
	}
	return policy, true, nil
}

func (s *Store) publishedPolicy(tenantID, policyID string, version uint64) (policymodel.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest policymodel.Policy
	var ok bool
	for _, policy := range s.Policies {
		if tenantID != "" && policy.TenantID != tenantID {
			continue
		}
		if policy.PolicyID != policyID || !policy.Published {
			continue
		}
		if version != 0 && policy.Version != version {
			continue
		}
		if version != 0 {
			return policy, true
		}
		if !ok || policy.Version > latest.Version {
			latest = policy
			ok = true
		}
	}
	return latest, ok
}

func (s *Store) AssignPolicy(assignment policymodel.Assignment) (policymodel.Assignment, bool, error) {
	if assignment.PolicyID == "" {
		return policymodel.Assignment{}, false, nil
	}
	if assignment.TenantID == "" {
		assignment.TenantID = "default"
	}
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	if err := s.loadAssignmentState(assignment); err != nil {
		return policymodel.Assignment{}, false, err
	}
	s.mu.RLock()
	policies := append([]policymodel.Policy(nil), s.Policies...)
	assignments := append([]policymodel.Assignment(nil), s.Assignments...)
	backend, ctx := s.backend, s.baseCtx
	s.mu.RUnlock()
	assignment, _, ok := prepareAssignment(policies, assignments, assignment)
	if !ok {
		return policymodel.Assignment{}, false, nil
	}
	if backend != nil {
		if err := backend.WriteAssignment(ctxOrBackground(ctx), assignment); err != nil {
			return policymodel.Assignment{}, false, fmt.Errorf("write policy assignment: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldAssignments := s.Assignments
	s.Assignments = upsertAssignmentSnapshot(s.Assignments, assignment)
	if err := s.persistFileLocked(); err != nil {
		s.Assignments = oldAssignments
		return policymodel.Assignment{}, false, fmt.Errorf("write policy assignment: %w", err)
	}
	return assignment, true, nil
}

func (s *Store) ListAssignments(tenantID, agentID string) []policymodel.Assignment {
	if backend, ctx := s.backendCtx(); backend != nil {
		if assignments, err := backend.ListAssignments(ctx, tenantID, agentID); err == nil {
			return assignments
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policymodel.Assignment, 0, len(s.Assignments))
	for _, assignment := range s.Assignments {
		if tenantID != "" && assignment.TenantID != tenantID {
			continue
		}
		if agentID != "" && assignment.AgentID != agentID {
			continue
		}
		out = append(out, assignment)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID == out[j].TenantID {
			return out[i].AssignmentID < out[j].AssignmentID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func (s *Store) EffectivePolicy(tenantID, agentID, scopeType, scopeSelector string) (policymodel.Policy, bool) {
	if backend, ctx := s.backendCtx(); backend != nil {
		if policy, ok, err := backend.EffectivePolicy(ctx, tenantID, agentID, scopeType, scopeSelector); err == nil && ok {
			return policy, true
		}
	}
	s.mu.RLock()
	assignments := append([]policymodel.Assignment(nil), s.Assignments...)
	s.mu.RUnlock()
	var best policymodel.Assignment
	bestRank := -1
	for _, assignment := range assignments {
		if tenantID != "" && assignment.TenantID != tenantID {
			continue
		}
		rank := AssignmentRank(assignment, agentID, scopeType, scopeSelector)
		if rank > bestRank {
			best = assignment
			bestRank = rank
		}
	}
	if bestRank >= 0 {
		return s.publishedPolicy(best.TenantID, best.PolicyID, best.PolicyVersion)
	}
	if tenantID == "" {
		tenantID = "default"
	}
	if policy, ok := s.publishedPolicy(tenantID, policymodel.DefaultPolicyID, 0); ok {
		return policy, true
	}
	return policymodel.ManagerDefaultPolicy(tenantID), true
}

func (s *Store) EffectivePolicyWithError(tenantID, agentID, scopeType, scopeSelector string) (policymodel.Policy, bool, error) {
	if backend, ctx := s.backendCtx(); backend != nil {
		policy, ok, err := backend.EffectivePolicy(ctx, tenantID, agentID, scopeType, scopeSelector)
		if err != nil {
			return policymodel.Policy{}, false, fmt.Errorf("read effective policy: %w", err)
		}
		return policy, ok, nil
	}
	policy, ok := s.EffectivePolicy(tenantID, agentID, scopeType, scopeSelector)
	return policy, ok, nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func assignmentKey(assignment policymodel.Assignment) string {
	parts := []string{
		assignment.TenantID,
		assignment.AgentID,
		assignment.Scope.Type,
		assignment.Scope.Selector,
		assignment.PolicyID,
	}
	return stableKey(parts...)
}

func sameAssignmentTarget(a, b policymodel.Assignment) bool {
	return a.TenantID == b.TenantID &&
		a.AgentID == b.AgentID &&
		a.Scope.Type == b.Scope.Type &&
		a.Scope.Selector == b.Scope.Selector
}

func AssignmentRank(assignment policymodel.Assignment, agentID, scopeType, scopeSelector string) int {
	if assignment.AgentID != "" {
		if agentID == "" || assignment.AgentID != agentID {
			return -1
		}
		return 30
	}
	if assignment.Scope.Type != "" {
		if assignment.Scope.Type != scopeType {
			return -1
		}
		if assignment.Scope.Selector != "" && assignment.Scope.Selector != scopeSelector {
			return -1
		}
		if assignment.Scope.Selector != "" {
			return 20
		}
		return 10
	}
	return 0
}
