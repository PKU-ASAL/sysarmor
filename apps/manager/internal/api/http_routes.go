package managerapi

import "net/http"

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

type overviewRoutes interface {
	Overview(http.ResponseWriter, *http.Request)
}

type unavailableSearchRoutes struct{}

func (unavailableSearchRoutes) Fields(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "search")
}
func (unavailableSearchRoutes) Search(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "search")
}
func (unavailableSearchRoutes) Histogram(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "search")
}

type unavailableTelemetryRoutes struct{}

func (unavailableTelemetryRoutes) Events(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "telemetry")
}
func (unavailableTelemetryRoutes) Signals(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "telemetry")
}
func (unavailableTelemetryRoutes) Incidents(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "telemetry")
}

type unavailableArtifactRoutes struct{}

func (unavailableArtifactRoutes) Artifacts(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "artifact")
}
func (unavailableArtifactRoutes) Artifact(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "artifact")
}
func (unavailableArtifactRoutes) Channels(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "artifact")
}

type unavailableResponseRoutes struct{}

func (unavailableResponseRoutes) Responses(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "response")
}
func (unavailableResponseRoutes) Decisions(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "response")
}
func (unavailableResponseRoutes) Approvals(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "response")
}
func (unavailableResponseRoutes) Acknowledgements(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "response")
}

type unavailableOverviewRoutes struct{}

func (unavailableOverviewRoutes) Overview(w http.ResponseWriter, _ *http.Request) {
	unavailable(w, "overview")
}

func unavailable(writer http.ResponseWriter, application string) {
	http.Error(writer, application+" application is not configured", http.StatusServiceUnavailable)
}

func (s *Server) SetPolicyRoutes(routes policyRoutes)         { s.policyRoutes = routes }
func (s *Server) SetIdentityRoutes(routes identityRoutes)     { s.identityRoutes = routes }
func (s *Server) SetEnrollmentRoutes(routes enrollmentRoutes) { s.enrollmentRoutes = routes }
func (s *Server) SetControlRoutes(routes controlRoutes)       { s.controlRoutes = routes }
func (s *Server) SetResponseRoutes(routes responseRoutes)     { s.responseRoutes = routes }
func (s *Server) SetArtifactRoutes(routes artifactRoutes)     { s.artifactRoutes = routes }
func (s *Server) SetTelemetryRoutes(routes telemetryRoutes)   { s.telemetryRoutes = routes }
func (s *Server) SetSearchRoutes(routes searchRoutes)         { s.searchRoutes = routes }
func (s *Server) SetOverviewRoutes(routes overviewRoutes)     { s.overviewRoutes = routes }
