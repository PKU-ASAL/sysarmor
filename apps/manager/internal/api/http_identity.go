package managerapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

// agentHealth is a write-only compatibility endpoint; reads are owned by Identity HTTP.
func (s *Server) agentHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && s.identityRoutes != nil {
		s.identityRoutes.Health(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireOperator(w, r, "admin") {
		return
	}
	var health agenthealth.AgentHealth
	if err := json.NewDecoder(r.Body).Decode(&health); err != nil {
		http.Error(w, fmt.Sprintf("decode agent health: %v", err), http.StatusBadRequest)
		return
	}
	if health.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	s.store.UpsertAgentHealth(health)
	if err := s.store.Save(); err != nil {
		http.Error(w, fmt.Sprintf("save store: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request, roles ...string) bool {
	if principal, ok := managerauth.PrincipalFromContext(r.Context()); ok {
		requiredRole := "operator"
		for _, role := range roles {
			if role == "admin" || role == "policy_admin" || role == "control_admin" || role == "incident_admin" {
				requiredRole = "admin"
			}
		}
		if principal.HasRole(requiredRole) {
			return true
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (s *Server) actorFromRequest(r *http.Request, _ string) string {
	if principal, ok := managerauth.PrincipalFromContext(r.Context()); ok {
		return principal.Subject
	}
	return ""
}
func (s *Server) roleFromRequest(r *http.Request, _ string) string {
	if principal, ok := managerauth.PrincipalFromContext(r.Context()); ok && len(principal.Roles) > 0 {
		return principal.Roles[0]
	}
	return ""
}
