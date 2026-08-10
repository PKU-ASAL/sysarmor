package managerapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func (s *Server) policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		if policyID := q.Get("policy_id"); policyID != "" {
			version := parseUint(q.Get("version"))
			policy, ok, err := s.store.GetPolicyWithError(q.Get("tenant_id"), policyID, version)
			if err != nil {
				http.Error(w, fmt.Sprintf("read policy: %v", err), http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "policy not found", http.StatusNotFound)
				return
			}
			writeJSON(w, policy)
			return
		}
		policies, err := s.store.ListPoliciesWithError(q.Get("tenant_id"))
		if err != nil {
			http.Error(w, fmt.Sprintf("read policies: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, policies)
	case http.MethodPost:
		if !s.requireOperator(w, r, "policy_admin") {
			return
		}
		var policy policymodel.Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, fmt.Sprintf("decode policy: %v", err), http.StatusBadRequest)
			return
		}
		if policy.PolicyID == "" {
			http.Error(w, "policy_id is required", http.StatusBadRequest)
			return
		}
		policy, err := s.store.UpsertPolicyWithError(policy)
		if err != nil {
			http.Error(w, fmt.Sprintf("save policy: %v", err), http.StatusInternalServerError)
			return
		}
		s.recordPolicyAudit(policymodel.AuditRecord{
			TenantID:      policy.TenantID,
			Action:        "policy.upsert",
			PolicyID:      policy.PolicyID,
			PolicyVersion: policy.Version,
			Actor:         s.actorFromRequest(r, r.URL.Query().Get("actor")),
			Reason:        r.URL.Query().Get("reason"),
		})
		if err := s.store.Save(); err != nil {
			http.Error(w, fmt.Sprintf("save store: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, policy)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) policyPublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireOperator(w, r, "policy_admin") {
		return
	}
	var req policyPublishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode policy publish: %v", err), http.StatusBadRequest)
		return
	}
	if req.PolicyID == "" {
		http.Error(w, "policy_id is required", http.StatusBadRequest)
		return
	}
	action := "policy.unpublish"
	if req.Published {
		action = "policy.publish"
	}
	policy, ok, err := s.store.PublishPolicyWithAudit(req.TenantID, req.PolicyID, req.Version, req.Published, policymodel.AuditRecord{
		Action: action,
		Actor:  s.actorFromRequest(r, req.Actor),
		Reason: req.Reason,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("save policy publication: %v", err), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	writeJSON(w, policy)
}

func (s *Server) policyAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	audits, err := s.store.ListPolicyAuditsWithError(q.Get("tenant_id"), q.Get("policy_id"))
	if err != nil {
		http.Error(w, fmt.Sprintf("read policy audits: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, audits)
}

func (s *Server) policyAssignments(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		assignments, err := s.store.ListAssignmentsWithError(q.Get("tenant_id"), q.Get("agent_id"))
		if err != nil {
			http.Error(w, fmt.Sprintf("read policy assignments: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, assignments)
	case http.MethodPost:
		if !s.requireOperator(w, r, "policy_admin") {
			return
		}
		var req policyAssignmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("decode assignment: %v", err), http.StatusBadRequest)
			return
		}
		if req.Downlink && !s.requireOperator(w, r, "control_admin") {
			return
		}
		assignment := req.Assignment
		var command *controlmodel.ControlCommand
		if req.Downlink {
			cmd, err := s.policyDownlinkCommand(r, assignment, req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			command = &cmd
		}
		saved, command, ok, err := s.store.AssignPolicyWithAudit(assignment, policymodel.AuditRecord{
			Action: "policy.assign",
			Actor:  s.actorFromRequest(r, req.Actor),
			Reason: req.Reason,
		}, command)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, fmt.Sprintf("save policy assignment: %v", err), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "policy not found or assignment invalid", http.StatusBadRequest)
			return
		}
		if command != nil {
			writeJSON(w, map[string]any{"assignment": saved, "control_command": command})
			return
		}
		writeJSON(w, saved)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) policyDownlinkCommand(r *http.Request, assignment policymodel.Assignment, req policyAssignmentRequest) (controlmodel.ControlCommand, error) {
	if strings.TrimSpace(assignment.AgentID) == "" {
		return controlmodel.ControlCommand{}, fmt.Errorf("downlink requires agent_id on policy assignment")
	}
	return controlmodel.ControlCommand{
		CommandID:     req.CommandID,
		TenantID:      assignment.TenantID,
		AgentID:       assignment.AgentID,
		Type:          controlmodel.ControlCommandTypePolicyUpdate,
		PolicyID:      assignment.PolicyID,
		PolicyVersion: assignment.PolicyVersion,
		Actor:         s.actorFromRequest(r, req.Actor),
		Reason:        firstNonEmptyString(req.Reason, "policy assignment downlink"),
	}, nil
}

func (s *Server) recordPolicyAudit(record policymodel.AuditRecord) {
	s.store.RecordPolicyAudit(record)
}

func (s *Server) effectivePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	policy, ok, err := s.store.EffectivePolicyWithError(q.Get("tenant_id"), q.Get("agent_id"), q.Get("scope_type"), q.Get("scope_selector"))
	if err != nil {
		http.Error(w, fmt.Sprintf("read effective policy: %v", err), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "effective policy not found", http.StatusNotFound)
		return
	}
	writeJSON(w, policy)
}
