package managerapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

type Server struct {
	searcher         platformopensearch.Searcher
	policyRoutes     policyRoutes
	identityRoutes   identityRoutes
	enrollmentRoutes enrollmentRoutes
	controlRoutes    controlRoutes
	responseRoutes   responseRoutes
	artifactRoutes   artifactRoutes
	telemetryRoutes  telemetryRoutes
	analysisRoutes   analysisRoutes
	searchRoutes     searchRoutes
	overviewRoutes   overviewRoutes
	statusRoutes     statusRoutes
}

type evidencePullbackRequest struct {
	RequestID  string            `json:"request_id"`
	TenantID   string            `json:"tenant_id"`
	AgentID    string            `json:"agent_id"`
	IncidentID string            `json:"incident_id,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Target     string            `json:"target,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Actor      string            `json:"actor,omitempty"`
}

type controlCommandRequest struct {
	Action         string          `json:"action,omitempty"`
	CommandID      string          `json:"command_id,omitempty"`
	TenantID       string          `json:"tenant_id,omitempty"`
	AgentID        string          `json:"agent_id"`
	Type           string          `json:"type"`
	PolicyID       string          `json:"policy_id,omitempty"`
	PolicyVersion  uint64          `json:"policy_version,omitempty"`
	ContentRef     string          `json:"content_ref,omitempty"`
	ContentKind    string          `json:"content_kind,omitempty"`
	ContentVersion string          `json:"content_version,omitempty"`
	PayloadJSON    json.RawMessage `json:"payload_json,omitempty"`
	Actor          string          `json:"actor,omitempty"`
	Reason         string          `json:"reason,omitempty"`
}

type AgentListItem struct {
	AgentID        string                       `json:"agent_id"`
	HostID         string                       `json:"host_id"`
	TenantID       string                       `json:"tenant_id"`
	Version        string                       `json:"version,omitempty"`
	AuthType       string                       `json:"auth_type,omitempty"`
	CertIdentity   string                       `json:"cert_identity,omitempty"`
	HealthStatus   string                       `json:"health_status,omitempty"`
	Scope          agenthealth.RuntimeScope     `json:"scope,omitempty"`
	Capability     agenthealth.SensorCapability `json:"sensor_capability,omitempty"`
	HealthObserved time.Time                    `json:"health_observed_at,omitempty"`
}

type DataResume struct {
	TenantID     string `json:"tenant_id"`
	AgentID      string `json:"agent_id"`
	SessionID    string `json:"session_id,omitempty"`
	ResumeCursor string `json:"resume_cursor,omitempty"`
}

func NewServer() *Server {
	return newServer(nil)
}

func NewServerWithSearch(searcher platformopensearch.Searcher) *Server {
	return newServer(searcher)
}

func newServer(searcher platformopensearch.Searcher) *Server {
	s := &Server{searcher: searcher, responseRoutes: unavailableResponseRoutes{},
		artifactRoutes: unavailableArtifactRoutes{}, telemetryRoutes: unavailableTelemetryRoutes{},
		analysisRoutes: unavailableAnalysisRoutes{},
		searchRoutes:   unavailableSearchRoutes{}, overviewRoutes: unavailableOverviewRoutes{},
		statusRoutes: unavailableStatusRoutes{}, policyRoutes: unavailablePolicyRoutes{},
		identityRoutes: unavailableIdentityRoutes{}}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.statusRoutes.Health)
	mux.HandleFunc("/api/v1/recompute", s.analysisRoutes.Recompute)
	mux.HandleFunc("/api/v1/rules", s.policyRoutes.Rules)
	mux.HandleFunc("/api/v1/policies", s.policyRoutes.Policies)
	mux.HandleFunc("/api/v1/policy-publish", s.policyRoutes.Publish)
	mux.HandleFunc("/api/v1/policy-audit", s.policyRoutes.Audits)
	mux.HandleFunc("/api/v1/policy-assignments", s.policyRoutes.Assignments)
	mux.HandleFunc("/api/v1/effective-policy", s.policyRoutes.Effective)
	mux.HandleFunc("/api/v1/artifacts", s.artifactRoutes.Artifacts)
	mux.HandleFunc("/api/v1/artifacts/", s.artifactRoutes.Artifact)
	mux.HandleFunc("/api/v1/channels", s.artifactRoutes.Channels)
	mux.HandleFunc("/api/v1/enrollments", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.Enrollments(w, r)
	})
	mux.HandleFunc("/api/v1/enrollment-artifact", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.Artifact(w, r)
	})
	mux.HandleFunc("/api/v1/enrollment-certificate", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.Certificate(w, r)
	})
	mux.HandleFunc("/api/v1/unenrollment-completions", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.Completion(w, r)
	})
	mux.HandleFunc("/api/v1/agent-install.sh", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.Install(w, r)
	})
	mux.HandleFunc("/api/v1/policy-rollouts", s.policyRoutes.Rollouts)
	mux.HandleFunc("/api/v1/responses", s.responseRoutes.Responses)
	mux.HandleFunc("/api/v1/response-decisions", s.responseRoutes.Decisions)
	mux.HandleFunc("/api/v1/response-approvals", s.responseRoutes.Approvals)
	mux.HandleFunc("/api/v1/response-acks", s.responseRoutes.Acknowledgements)
	mux.HandleFunc("/api/v1/data-resume", s.identityRoutes.Resume)
	mux.HandleFunc("/api/v1/evidence-pullbacks", s.handleEvidencePullbacks)
	mux.HandleFunc("/api/v1/control-commands", s.handleControlCommands)
	mux.HandleFunc("/api/v1/ui/overview", s.overviewRoutes.Overview)
	mux.HandleFunc("/api/v1/ui/deploy/options", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.DeployOptions(w, r)
	})
	mux.HandleFunc("/api/v1/ui/deploy/agent-command", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.DeployAgentCommand(w, r)
	})
	mux.HandleFunc("/api/v1/search/fields", s.searchRoutes.Fields)
	mux.HandleFunc("/api/v1/search/histogram", s.searchRoutes.Histogram)
	mux.HandleFunc("/api/v1/search", s.searchRoutes.Search)
	mux.HandleFunc("/api/v1/agents", s.identityRoutes.Agents)
	mux.HandleFunc("/api/v1/agent-sessions", s.identityRoutes.Sessions)
	mux.HandleFunc("/api/v1/metrics", s.identityRoutes.Metrics)
	mux.HandleFunc("/api/v1/rarity-baseline", s.identityRoutes.Rarity)
	mux.HandleFunc("/api/v1/agent-health", s.identityRoutes.Health)
	mux.HandleFunc("/api/v1/events", s.telemetryRoutes.Events)
	mux.HandleFunc("/api/v1/signals", s.telemetryRoutes.Signals)
	mux.HandleFunc("/api/v1/incidents", s.telemetryRoutes.Incidents)
	mux.HandleFunc("/api/v1/store-status", s.statusRoutes.StoreStatus)
	return limitRequestBody(normalizeAPIErrors(requireProductionPrincipal(mux)), maxManagerRequestBody)
}

func (s *Server) handleEvidencePullbacks(w http.ResponseWriter, r *http.Request) {
	if s.controlRoutes == nil {
		http.Error(w, "control application is not configured", http.StatusServiceUnavailable)
		return
	}
	s.controlRoutes.Evidence(w, r)
}

func (s *Server) handleControlCommands(w http.ResponseWriter, r *http.Request) {
	if s.controlRoutes == nil {
		http.Error(w, "control application is not configured", http.StatusServiceUnavailable)
		return
	}
	s.controlRoutes.Commands(w, r)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func parseUint(raw string) uint64 {
	if raw == "" {
		return 0
	}
	v, _ := strconv.ParseUint(raw, 10, 64)
	return v
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
