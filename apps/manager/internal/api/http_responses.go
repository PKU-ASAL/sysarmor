package managerapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

func (s *Server) responses(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		if q.Get("pending") == "true" {
			responses, err := s.store.PendingResponsesWithError(q.Get("tenant_id"), q.Get("agent_id"))
			if err != nil {
				http.Error(w, fmt.Sprintf("read pending responses: %v", err), http.StatusInternalServerError)
				return
			}
			writeJSON(w, responses)
			return
		}
		responses, err := s.store.ListResponsesWithError(q.Get("tenant_id"), q.Get("agent_id"))
		if err != nil {
			http.Error(w, fmt.Sprintf("read responses: %v", err), http.StatusInternalServerError)
			return
		}
		writeJSON(w, responses)
	case http.MethodPost:
		if !s.requireOperator(w, r, "responder") {
			return
		}
		var cmd responsemodel.Command
		if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
			http.Error(w, fmt.Sprintf("decode response command: %v", err), http.StatusBadRequest)
			return
		}
		cmd.Actor = s.actorFromRequest(r, cmd.Actor)
		s.createResponse(w, cmd)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) responseDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireOperator(w, r, "responder") {
		return
	}
	var req responseDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode response decision: %v", err), http.StatusBadRequest)
		return
	}
	if req.SignalID == "" {
		http.Error(w, "signal_id is required", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	tenantID := requestTenantID(r)
	sig, ok := s.store.GetSignalForTenant(tenantID, req.SignalID)
	if !ok {
		http.Error(w, "signal not found", http.StatusNotFound)
		return
	}
	intent := sig.GetResponseIntent()
	if intent == nil || intent.GetResponseIntent() == "" {
		http.Error(w, "signal response intent not found", http.StatusBadRequest)
		return
	}
	action := intent.GetRecommendedAction()
	if action == "" {
		action = intent.GetResponseIntent()
	}
	target := req.Target
	if target == "" {
		target = signalResponseTarget(sig)
	}
	reason := fmt.Sprintf("signal=%s name=%s response_intent=%s confidence=%d", sig.GetId(), sig.GetName(), intent.GetResponseIntent(), intent.GetConfidence())
	if intent.GetReason() != "" {
		reason += " reason=" + intent.GetReason()
	}
	cmd := responsemodel.Command{
		ResponseID: "resp-" + sig.GetId(),
		TenantID:   tenantID,
		AgentID:    req.AgentID,
		SignalID:   sig.GetId(),
		Labels:     cloneStringMap(sig.GetLabels()),
		Scope:      req.Scope,
		Action:     action,
		Mode:       responsemodel.DefaultMode,
		Target:     target,
		Reason:     reason,
		Actor:      s.actorFromRequest(r, req.Actor),
	}
	s.createResponse(w, cmd)
}

func (s *Server) responseApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireOperator(w, r, "responder") {
		return
	}
	var req responseApprovalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decode response approval: %v", err), http.StatusBadRequest)
		return
	}
	if req.ResponseID == "" {
		http.Error(w, "response_id is required", http.StatusBadRequest)
		return
	}
	cmd, ok := s.store.ApproveResponse(req.TenantID, req.AgentID, req.ResponseID, req.Approved, s.actorFromRequest(r, req.Actor), s.roleFromRequest(r, req.Role), req.Reason)
	if !ok {
		http.Error(w, "response command not found", http.StatusNotFound)
		return
	}
	if err := s.store.Save(); err != nil {
		http.Error(w, fmt.Sprintf("save store: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, responsemodel.AuditRecord{Command: cmd})
}

func (s *Server) createResponse(w http.ResponseWriter, cmd responsemodel.Command) {
	if cmd.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if cmd.TenantID == "" {
		cmd.TenantID = "default"
	}
	if health, ok, err := s.store.GetAgentHealthWithError(cmd.TenantID, cmd.AgentID); err != nil {
		http.Error(w, fmt.Sprintf("read agent health: %v", err), http.StatusInternalServerError)
		return
	} else if ok {
		if cmd.Scope.Type == "" && cmd.Scope.Selector == "" {
			cmd.Scope = responsemodel.Scope{Type: health.Scope.Type, Selector: health.Scope.Selector}
		}
		if decision := responsemodel.ScopeDecision(cmd.Scope, responsemodel.Scope{Type: health.Scope.Type, Selector: health.Scope.Selector}, true); !decision.Allowed {
			s.denyResponse(w, cmd, decision)
			return
		}
	} else if cmd.Scope.Type != "" || cmd.Scope.Selector != "" {
		s.denyResponse(w, cmd, responsemodel.Decision{Allowed: false, Reason: "agent runtime scope is required for scoped response command"})
		return
	}
	responsePolicy := responsemodel.DefaultPolicy()
	if policy, ok, err := s.store.EffectivePolicyWithError(cmd.TenantID, cmd.AgentID, cmd.Scope.Type, cmd.Scope.Selector); err != nil {
		http.Error(w, fmt.Sprintf("read effective policy: %v", err), http.StatusInternalServerError)
		return
	} else if ok {
		responsePolicy = policy.Response
		if len(responsePolicy.AllowedActions) == 0 && len(responsePolicy.AllowedModes) == 0 {
			responsePolicy = responsemodel.DefaultPolicy()
		}
		if cmd.PolicyID == "" {
			cmd.PolicyID = policy.PolicyID
			cmd.PolicyVersion = policy.Version
		}
	}
	if cmd.PolicyID == "" {
		policy, _, err := s.store.EffectivePolicyWithError(cmd.TenantID, cmd.AgentID, cmd.Scope.Type, cmd.Scope.Selector)
		if err != nil {
			http.Error(w, fmt.Sprintf("read effective policy: %v", err), http.StatusInternalServerError)
			return
		}
		cmd.PolicyID = policy.PolicyID
		cmd.PolicyVersion = policy.Version
	}
	cmd = responsemodel.ApplyPolicyRequirements(cmd, responsePolicy)
	if decision := responsemodel.ValidateCommandWithPolicy(cmd, responsePolicy); !decision.Allowed {
		s.denyResponse(w, cmd, decision)
		return
	}
	if cmd.ApprovalRequired {
		cmd = responsemodel.NormalizeCommand(cmd)
		cmd.Status = "pending_approval"
		cmd.ApprovalStatus = "required"
	}
	cmd, err := s.store.CreateResponse(cmd)
	if err != nil {
		http.Error(w, fmt.Sprintf("save response: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, cmd)
}

func (s *Server) denyResponse(w http.ResponseWriter, cmd responsemodel.Command, decision responsemodel.Decision) {
	cmd = responsemodel.NormalizeCommand(cmd)
	cmd.Status = "denied"
	if cmd.Reason == "" {
		cmd.Reason = decision.Reason
	} else {
		cmd.Reason = cmd.Reason + "; denied: " + decision.Reason
	}
	var err error
	cmd, err = s.store.CreateResponse(cmd)
	if err != nil {
		http.Error(w, fmt.Sprintf("save response: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusForbidden)
	writeJSON(w, responsemodel.AuditRecord{Command: cmd})
}

func signalResponseTarget(sig *signalv1.Signal) string {
	for _, entity := range sig.GetEntities() {
		if entity.GetKind() == "process" && entity.GetKey() != "" {
			return entity.GetKey()
		}
	}
	for _, entity := range sig.GetEntities() {
		if entity.GetKey() != "" {
			return entity.GetKey()
		}
	}
	return ""
}

func (s *Server) responseAcks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireOperator(w, r, "response_admin") {
		return
	}
	var ack responsemodel.Ack
	if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
		http.Error(w, fmt.Sprintf("decode response ack: %v", err), http.StatusBadRequest)
		return
	}
	if ack.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if _, ok, err := s.store.AckResponse(ack); err != nil {
		http.Error(w, fmt.Sprintf("save response ack: %v", err), http.StatusInternalServerError)
		return
	} else if !ok {
		http.Error(w, "response command not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
