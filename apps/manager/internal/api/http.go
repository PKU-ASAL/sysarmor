package managerapi

import (
	"context"
	"encoding/json"
	"fmt"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	ingest "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/ingest"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	store            ManagerStore
	searcher         platformopensearch.Searcher
	localTelemetry   bool
	policyRoutes     policyRoutes
	identityRoutes   identityRoutes
	enrollmentRoutes enrollmentRoutes
	controlRoutes    controlRoutes
	responseRoutes   responseRoutes
	artifactRoutes   artifactRoutes
	telemetryRoutes  telemetryRoutes
	searchRoutes     searchRoutes
	identityQuery    identityQueries
	controlQuery     controlQueries
	identityResolve  func(*http.Request) (managerapp.RequestContext, error)
}

type identityQueries interface {
	ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error)
	GetHealth(context.Context, managerapp.RequestContext, domainidentity.AgentID) (domainidentity.Health, error)
	Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error)
	Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error)
	AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error)
}

type controlQueries interface {
	Commands(context.Context, managerapp.RequestContext, controlapp.CommandQuery) ([]domaincontrol.Command, error)
}

func (s *Server) SetIdentityApplication(query identityQueries, resolve func(*http.Request) (managerapp.RequestContext, error)) {
	s.identityQuery, s.identityResolve = query, resolve
}

func (s *Server) SetControlApplication(query controlQueries) { s.controlQuery = query }

func (s *Server) identityRequest(r *http.Request) (managerapp.RequestContext, error) {
	if s.identityResolve == nil {
		return managerapp.RequestContext{}, fmt.Errorf("identity application is not configured")
	}
	return s.identityResolve(r)
}

type policyRoutes interface {
	Policies(http.ResponseWriter, *http.Request)
	Publish(http.ResponseWriter, *http.Request)
	Audits(http.ResponseWriter, *http.Request)
	Assignments(http.ResponseWriter, *http.Request)
	Effective(http.ResponseWriter, *http.Request)
}

type identityRoutes interface {
	Agents(http.ResponseWriter, *http.Request)
	Health(http.ResponseWriter, *http.Request)
	Sessions(http.ResponseWriter, *http.Request)
	Resume(http.ResponseWriter, *http.Request)
	Metrics(http.ResponseWriter, *http.Request)
	Rarity(http.ResponseWriter, *http.Request)
}

type enrollmentRoutes interface {
	Enrollments(http.ResponseWriter, *http.Request)
	Install(http.ResponseWriter, *http.Request)
	Artifact(http.ResponseWriter, *http.Request)
	DeployOptions(http.ResponseWriter, *http.Request)
	DeployAgentCommand(http.ResponseWriter, *http.Request)
	Certificate(http.ResponseWriter, *http.Request)
	Completion(http.ResponseWriter, *http.Request)
}

type controlRoutes interface {
	Commands(http.ResponseWriter, *http.Request)
	Evidence(http.ResponseWriter, *http.Request)
}

type responseRoutes interface {
	Responses(http.ResponseWriter, *http.Request)
	Decisions(http.ResponseWriter, *http.Request)
	Approvals(http.ResponseWriter, *http.Request)
	Acknowledgements(http.ResponseWriter, *http.Request)
}

type artifactRoutes interface {
	Artifacts(http.ResponseWriter, *http.Request)
	Artifact(http.ResponseWriter, *http.Request)
	Channels(http.ResponseWriter, *http.Request)
}

type telemetryRoutes interface {
	Events(http.ResponseWriter, *http.Request)
	Signals(http.ResponseWriter, *http.Request)
	Incidents(http.ResponseWriter, *http.Request)
}

type searchRoutes interface {
	Fields(http.ResponseWriter, *http.Request)
	Search(http.ResponseWriter, *http.Request)
	Histogram(http.ResponseWriter, *http.Request)
}

type unavailableSearchRoutes struct{}

func (unavailableSearchRoutes) Fields(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "search application is not configured", http.StatusServiceUnavailable)
}
func (unavailableSearchRoutes) Search(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "search application is not configured", http.StatusServiceUnavailable)
}
func (unavailableSearchRoutes) Histogram(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "search application is not configured", http.StatusServiceUnavailable)
}

type unavailableTelemetryRoutes struct{}

func (unavailableTelemetryRoutes) Events(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "telemetry application is not configured", http.StatusServiceUnavailable)
}
func (unavailableTelemetryRoutes) Signals(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "telemetry application is not configured", http.StatusServiceUnavailable)
}
func (unavailableTelemetryRoutes) Incidents(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "telemetry application is not configured", http.StatusServiceUnavailable)
}

type unavailableArtifactRoutes struct{}

func (unavailableArtifactRoutes) Artifacts(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "artifact application is not configured", http.StatusServiceUnavailable)
}
func (unavailableArtifactRoutes) Artifact(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "artifact application is not configured", http.StatusServiceUnavailable)
}
func (unavailableArtifactRoutes) Channels(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "artifact application is not configured", http.StatusServiceUnavailable)
}

type unavailableResponseRoutes struct{}

func (unavailableResponseRoutes) Responses(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "response application is not configured", http.StatusServiceUnavailable)
}
func (unavailableResponseRoutes) Decisions(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "response application is not configured", http.StatusServiceUnavailable)
}
func (unavailableResponseRoutes) Approvals(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "response application is not configured", http.StatusServiceUnavailable)
}
func (unavailableResponseRoutes) Acknowledgements(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "response application is not configured", http.StatusServiceUnavailable)
}

func (s *Server) SetPolicyRoutes(routes policyRoutes)         { s.policyRoutes = routes }
func (s *Server) SetIdentityRoutes(routes identityRoutes)     { s.identityRoutes = routes }
func (s *Server) SetEnrollmentRoutes(routes enrollmentRoutes) { s.enrollmentRoutes = routes }
func (s *Server) SetControlRoutes(routes controlRoutes)       { s.controlRoutes = routes }
func (s *Server) SetResponseRoutes(routes responseRoutes)     { s.responseRoutes = routes }
func (s *Server) SetArtifactRoutes(routes artifactRoutes)     { s.artifactRoutes = routes }
func (s *Server) SetTelemetryRoutes(routes telemetryRoutes)   { s.telemetryRoutes = routes }
func (s *Server) SetSearchRoutes(routes searchRoutes)         { s.searchRoutes = routes }

type policyPublishRequest struct {
	TenantID  string `json:"tenant_id"`
	PolicyID  string `json:"policy_id"`
	Version   uint64 `json:"version"`
	Published bool   `json:"published"`
	Actor     string `json:"actor,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type policyAssignmentRequest struct {
	policymodel.Assignment
	Actor     string `json:"actor,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Downlink  bool   `json:"downlink,omitempty"`
	CommandID string `json:"command_id,omitempty"`
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

func NewServer(st ManagerStore) *Server {
	st.EnsureDefaultPolicy("default")
	s := newServer(st, nil)
	s.localTelemetry = true
	return s
}

func NewServerWithSearch(st ManagerStore, searcher platformopensearch.Searcher) *Server {
	st.EnsureDefaultPolicy("default")
	s := newServer(st, searcher)
	s.localTelemetry = true
	return s
}

func NewProductionServerWithSearch(st ManagerStore, searcher platformopensearch.Searcher) (*Server, error) {
	s := newServer(st, searcher)
	if err := st.EnsureDefaultPolicyWithError("default"); err != nil {
		return nil, fmt.Errorf("initialize production default policy: %w", err)
	}
	return s, nil
}

func newServer(st ManagerStore, searcher platformopensearch.Searcher) *Server {
	s := &Server{store: st, searcher: searcher, responseRoutes: unavailableResponseRoutes{},
		artifactRoutes: unavailableArtifactRoutes{}, telemetryRoutes: unavailableTelemetryRoutes{},
		searchRoutes: unavailableSearchRoutes{}}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/api/v1/recompute", s.recompute)
	mux.HandleFunc("/api/v1/rules", s.rules)
	if s.policyRoutes == nil {
		mux.HandleFunc("/api/v1/policies", s.policies)
		mux.HandleFunc("/api/v1/policy-publish", s.policyPublish)
		mux.HandleFunc("/api/v1/policy-audit", s.policyAudit)
		mux.HandleFunc("/api/v1/policy-assignments", s.policyAssignments)
		mux.HandleFunc("/api/v1/effective-policy", s.effectivePolicy)
	} else {
		mux.HandleFunc("/api/v1/policies", s.policyRoutes.Policies)
		mux.HandleFunc("/api/v1/policy-publish", s.policyRoutes.Publish)
		mux.HandleFunc("/api/v1/policy-audit", s.policyRoutes.Audits)
		mux.HandleFunc("/api/v1/policy-assignments", s.policyRoutes.Assignments)
		mux.HandleFunc("/api/v1/effective-policy", s.policyRoutes.Effective)
	}
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
	mux.HandleFunc("/api/v1/policy-rollouts", s.policyRollouts)
	mux.HandleFunc("/api/v1/responses", s.responseRoutes.Responses)
	mux.HandleFunc("/api/v1/response-decisions", s.responseRoutes.Decisions)
	mux.HandleFunc("/api/v1/response-approvals", s.responseRoutes.Approvals)
	mux.HandleFunc("/api/v1/response-acks", s.responseRoutes.Acknowledgements)
	if s.identityRoutes != nil {
		mux.HandleFunc("/api/v1/data-resume", s.identityRoutes.Resume)
	}
	mux.HandleFunc("/api/v1/evidence-pullbacks", s.handleEvidencePullbacks)
	mux.HandleFunc("/api/v1/control-commands", s.handleControlCommands)
	mux.HandleFunc("/api/v1/ui/overview", s.uiOverview)
	mux.HandleFunc("/api/v1/ui/deploy/options", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.DeployOptions(w, r)
	})
	mux.HandleFunc("/api/v1/ui/deploy/agent-command", func(w http.ResponseWriter, r *http.Request) {
		s.enrollmentRoutes.DeployAgentCommand(w, r)
	})
	mux.HandleFunc("/api/v1/search/fields", s.searchRoutes.Fields)
	mux.HandleFunc("/api/v1/search/histogram", s.searchRoutes.Histogram)
	mux.HandleFunc("/api/v1/search", s.searchRoutes.Search)
	if s.identityRoutes != nil {
		mux.HandleFunc("/api/v1/agents", s.identityRoutes.Agents)
		mux.HandleFunc("/api/v1/agent-sessions", s.identityRoutes.Sessions)
		mux.HandleFunc("/api/v1/metrics", s.identityRoutes.Metrics)
		mux.HandleFunc("/api/v1/rarity-baseline", s.identityRoutes.Rarity)
	}
	mux.HandleFunc("/api/v1/agent-health", s.agentHealth)
	mux.HandleFunc("/api/v1/events", s.telemetryRoutes.Events)
	mux.HandleFunc("/api/v1/signals", s.telemetryRoutes.Signals)
	mux.HandleFunc("/api/v1/incidents", s.telemetryRoutes.Incidents)
	mux.HandleFunc("/api/v1/store-status", s.storeStatus)
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

func parseLabelSelector(values []string) store.LabelSelector {
	labels := store.LabelSelector{}
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			continue
		}
		labels[key] = value
	}
	return labels
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

func removeString(in []string, value string) []string {
	out := make([]string, 0, len(in))
	for _, item := range in {
		if item != value {
			out = append(out, item)
		}
	}
	return out
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

func pageSlice[T any](in []T, limit, offset uint64) []T {
	if offset >= uint64(len(in)) {
		return []T{}
	}
	out := in[offset:]
	if limit > 0 && limit < uint64(len(out)) {
		out = out[:limit]
	}
	return out
}

func writeProtoJSON(w http.ResponseWriter, msg proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		http.Error(w, fmt.Sprintf("encode proto json: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(append(data, '\n'))
}

func writeSignalList(w http.ResponseWriter, signals []*signalv1.Signal) {
	w.Header().Set("Content-Type", "application/json")
	raw := make([]json.RawMessage, 0, len(signals))
	for _, sig := range signals {
		raw = append(raw, mustProtoJSON(sig))
	}
	_ = json.NewEncoder(w).Encode(raw)
}

func writeRawList(w http.ResponseWriter, raw []json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(raw)
}

func writeEventList(w http.ResponseWriter, events []*eventv1.CanonicalEvent) {
	w.Header().Set("Content-Type", "application/json")
	raw := make([]json.RawMessage, 0, len(events))
	for _, ev := range events {
		raw = append(raw, mustProtoJSON(ev))
	}
	_ = json.NewEncoder(w).Encode(raw)
}

func writeIncidentList(w http.ResponseWriter, incidents []*incidentv1.Incident) {
	w.Header().Set("Content-Type", "application/json")
	raw := make([]json.RawMessage, 0, len(incidents))
	for _, inc := range incidents {
		raw = append(raw, mustProtoJSON(inc))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"incidents": raw})
}

func writeAnalysisResult(w http.ResponseWriter, result ingest.Result) {
	w.Header().Set("Content-Type", "application/json")
	cloud := make([]json.RawMessage, 0, len(result.CloudSignals))
	for _, sig := range result.CloudSignals {
		cloud = append(cloud, mustProtoJSON(sig))
	}
	incidents := make([]json.RawMessage, 0, len(result.Incidents))
	for _, inc := range result.Incidents {
		incidents = append(incidents, mustProtoJSON(inc))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"cloud_signals": cloud, "incidents": incidents})
}

func mustProtoJSON(msg proto.Message) json.RawMessage {
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}
