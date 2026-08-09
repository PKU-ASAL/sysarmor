package managerapi

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	ingest "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/ingest"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	store           ManagerStore
	searcher        platformopensearch.Searcher
	artifactDir     string
	artifactPub     []byte
	caCert          *x509.Certificate
	caCertPEM       []byte
	caKey           *rsa.PrivateKey
	localTelemetry  bool
	policyRoutes    policyRoutes
	identityRoutes  identityRoutes
	identityQuery   identityQueries
	identityResolve func(*http.Request) (managerapp.RequestContext, error)
}

type identityQueries interface {
	ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error)
	GetHealth(context.Context, managerapp.RequestContext, domainidentity.AgentID) (domainidentity.Health, error)
	Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error)
	Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error)
	AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error)
}

func (s *Server) SetIdentityApplication(query identityQueries, resolve func(*http.Request) (managerapp.RequestContext, error)) {
	s.identityQuery, s.identityResolve = query, resolve
}

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

func (s *Server) SetPolicyRoutes(routes policyRoutes)     { s.policyRoutes = routes }
func (s *Server) SetIdentityRoutes(routes identityRoutes) { s.identityRoutes = routes }

type responseDecisionRequest struct {
	SignalID string              `json:"signal_id"`
	TenantID string              `json:"tenant_id"`
	AgentID  string              `json:"agent_id"`
	Scope    responsemodel.Scope `json:"scope,omitempty"`
	Target   string              `json:"target,omitempty"`
	Actor    string              `json:"actor,omitempty"`
}

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

type enrollmentRequest struct {
	TenantID    string            `json:"tenant_id,omitempty"`
	AgentID     string            `json:"agent_id,omitempty"`
	HostID      string            `json:"host_id,omitempty"`
	GatewayAddr string            `json:"gateway_addr"`
	GatewaySNI  string            `json:"gateway_sni,omitempty"`
	Profile     string            `json:"profile,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	ArtifactID  string            `json:"artifact_id,omitempty"`
	ArtifactURL string            `json:"artifact_url,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	TTL         string            `json:"ttl,omitempty"`
	Actor       string            `json:"actor,omitempty"`
}

type channelRequest struct {
	TenantID   string `json:"tenant_id,omitempty"`
	Channel    string `json:"channel"`
	ArtifactID string `json:"artifact_id"`
	Actor      string `json:"actor,omitempty"`
}

type certificateRequest struct {
	Token string `json:"token,omitempty"`
	CSR   string `json:"csr"`
}

type responseApprovalRequest struct {
	ResponseID string `json:"response_id"`
	TenantID   string `json:"tenant_id"`
	AgentID    string `json:"agent_id"`
	Approved   bool   `json:"approved"`
	Actor      string `json:"actor,omitempty"`
	Role       string `json:"role,omitempty"`
	Reason     string `json:"reason,omitempty"`
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
	var err error
	if s.artifactPub, err = readRequiredFile("SYSARMOR_ARTIFACT_PUBLIC_KEY"); err != nil {
		return nil, err
	}
	if s.caCertPEM, err = readRequiredFile("SYSARMOR_AGENT_CA_CERT"); err != nil {
		return nil, err
	}
	caKeyPEM, err := readRequiredFile("SYSARMOR_AGENT_CA_KEY")
	if err != nil {
		return nil, err
	}
	s.caCert, s.caKey, err = parseCARequired(s.caCertPEM, caKeyPEM)
	if err != nil {
		return nil, err
	}
	if err := st.EnsureDefaultPolicyWithError("default"); err != nil {
		return nil, fmt.Errorf("initialize production default policy: %w", err)
	}
	return s, nil
}

func newServer(st ManagerStore, searcher platformopensearch.Searcher) *Server {
	s := &Server{store: st, searcher: searcher, artifactDir: defaultArtifactDir()}
	s.artifactPub = readOptionalFile(os.Getenv("SYSARMOR_ARTIFACT_PUBLIC_KEY"))
	s.caCertPEM = readOptionalFile(os.Getenv("SYSARMOR_AGENT_CA_CERT"))
	caKeyPEM := readOptionalFile(os.Getenv("SYSARMOR_AGENT_CA_KEY"))
	if len(s.caCertPEM) > 0 && len(caKeyPEM) > 0 {
		s.caCert, s.caKey = parseCA(s.caCertPEM, caKeyPEM)
	}
	return s
}

func defaultArtifactDir() string {
	if v := strings.TrimSpace(os.Getenv("SYSARMOR_ARTIFACT_DIR")); v != "" {
		return v
	}
	return "/var/lib/sysarmor/manager/artifacts"
}

func readOptionalFile(path string) []byte {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func readRequiredFile(envName string) ([]byte, error) {
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		return nil, fmt.Errorf("%s is required", envName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", envName, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", envName)
	}
	return data, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey) {
	cert, key, _ := parseCARequired(certPEM, keyPEM)
	return cert, key
}

func parseCARequired(certPEM, keyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, fmt.Errorf("decode agent CA cert/key PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse agent CA cert: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse agent CA key: %w", err)
		}
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("agent CA key must be RSA")
		}
		key = rsaKey
	}
	return cert, key, nil
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
	mux.HandleFunc("/api/v1/artifacts", s.artifacts)
	mux.HandleFunc("/api/v1/artifacts/", s.artifactByID)
	mux.HandleFunc("/api/v1/channels", s.channels)
	mux.HandleFunc("/api/v1/enrollments", s.enrollments)
	mux.HandleFunc("/api/v1/enrollment-artifact", s.enrollmentArtifact)
	mux.HandleFunc("/api/v1/enrollment-certificate", s.enrollmentCertificate)
	mux.HandleFunc("/api/v1/unenrollment-completions", s.unenrollmentCompletion)
	mux.HandleFunc("/api/v1/agent-install.sh", s.agentInstallScript)
	mux.HandleFunc("/api/v1/policy-rollouts", s.policyRollouts)
	mux.HandleFunc("/api/v1/responses", s.responses)
	mux.HandleFunc("/api/v1/response-decisions", s.responseDecisions)
	mux.HandleFunc("/api/v1/response-approvals", s.responseApprovals)
	mux.HandleFunc("/api/v1/response-acks", s.responseAcks)
	if s.identityRoutes != nil {
		mux.HandleFunc("/api/v1/data-resume", s.identityRoutes.Resume)
	}
	mux.HandleFunc("/api/v1/evidence-pullbacks", s.evidencePullbacks)
	mux.HandleFunc("/api/v1/control-commands", s.controlCommands)
	mux.HandleFunc("/api/v1/ui/overview", s.uiOverview)
	mux.HandleFunc("/api/v1/ui/deploy/options", s.uiDeployOptions)
	mux.HandleFunc("/api/v1/ui/deploy/agent-command", s.uiDeployAgentCommand)
	mux.HandleFunc("/api/v1/search/fields", s.searchFields)
	mux.HandleFunc("/api/v1/search/histogram", s.searchHistogram)
	mux.HandleFunc("/api/v1/search", s.search)
	if s.identityRoutes != nil {
		mux.HandleFunc("/api/v1/agents", s.identityRoutes.Agents)
		mux.HandleFunc("/api/v1/agent-sessions", s.identityRoutes.Sessions)
		mux.HandleFunc("/api/v1/metrics", s.identityRoutes.Metrics)
		mux.HandleFunc("/api/v1/rarity-baseline", s.identityRoutes.Rarity)
	}
	mux.HandleFunc("/api/v1/agent-health", s.agentHealth)
	mux.HandleFunc("/api/v1/events", s.events)
	mux.HandleFunc("/api/v1/signals", s.signals)
	mux.HandleFunc("/api/v1/incidents", s.incidents)
	mux.HandleFunc("/api/v1/store-status", s.storeStatus)
	return limitRequestBody(normalizeAPIErrors(requireProductionPrincipal(mux)), maxManagerRequestBody)
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
