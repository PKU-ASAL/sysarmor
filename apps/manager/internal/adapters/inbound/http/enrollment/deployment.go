package enrollment

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type deployAgentCommandRequest struct {
	TenantID          string            `json:"tenant_id,omitempty"`
	AgentID           string            `json:"agent_id,omitempty"`
	HostID            string            `json:"host_id,omitempty"`
	GatewayAddress    string            `json:"gateway_addr,omitempty"`
	GatewayServerName string            `json:"gateway_sni,omitempty"`
	Profile           string            `json:"profile,omitempty"`
	Channel           string            `json:"channel,omitempty"`
	ArtifactID        string            `json:"artifact_id,omitempty"`
	TTL               string            `json:"ttl,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
}

type deployCommandArtifact struct {
	ArtifactID  string `json:"artifact_id,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
}

func (handler *Handler) DeployAgentCommand(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolveRequest(writer, request)
	if !ok {
		return
	}
	command, err := handler.decodeDeployCommand(request, requestContext.Actor.TenantID.String())
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	result, err := handler.create.Execute(request.Context(), requestContext, command)
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	handler.writeDeployCommand(writer, request, result)
}

func (handler *Handler) decodeDeployCommand(request *http.Request, actorTenant string) (enrollmentapp.CreateEnrollmentCommand, error) {
	var input deployAgentCommandRequest
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		return enrollmentapp.CreateEnrollmentCommand{}, failure.New(failure.InvalidArgument, "decode deploy command")
	}
	profile := defaultEnrollmentString(strings.TrimSpace(input.Profile), "linux-systemd")
	if !deployChannelMatchesProfile(profile, input.Channel) {
		return enrollmentapp.CreateEnrollmentCommand{}, failure.New(failure.InvalidArgument, "channel profile mismatch")
	}
	ttl, err := deploymentTTL(input.TTL)
	if err != nil {
		return enrollmentapp.CreateEnrollmentCommand{}, err
	}
	return enrollmentapp.CreateEnrollmentCommand{TenantID: defaultEnrollmentString(strings.TrimSpace(input.TenantID), actorTenant),
		AgentID: input.AgentID, HostID: input.HostID,
		GatewayAddress:    defaultEnrollmentString(strings.TrimSpace(input.GatewayAddress), handler.deployGatewayAddress),
		GatewayServerName: defaultEnrollmentString(strings.TrimSpace(input.GatewayServerName), handler.deployGatewayServerName),
		Profile:           profile, Channel: input.Channel, ArtifactID: input.ArtifactID, Labels: input.Labels, TTL: ttl,
		FallbackToArtifact: true}, nil
}

func deploymentTTL(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return defaultEnrollmentTTL, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, failure.New(failure.InvalidArgument, "ttl is invalid")
	}
	return value, nil
}

func deployChannelMatchesProfile(profile, channel string) bool {
	channel = strings.TrimSpace(channel)
	if strings.HasPrefix(channel, "linux-container-") {
		return profile == "linux-container"
	}
	if strings.HasPrefix(channel, "linux-systemd-") {
		return profile == "linux-systemd"
	}
	return true
}

func (handler *Handler) writeDeployCommand(writer http.ResponseWriter, request *http.Request, result enrollmentapp.CreateEnrollmentResult) {
	enrollment := result.Enrollment
	scriptURL := handler.enrollmentInstallURL(request, result.BootstrapTicket)
	installCommand, entrypoint := "curl -fsSL "+shellQuote(scriptURL)+" | sudo bash", ""
	if enrollment.Profile == "linux-container" {
		installCommand = "curl -fsSL " + shellQuote(scriptURL) + " | bash"
		entrypoint = "/opt/sysarmor/agent/bin/sysarmor-agent run --config /etc/sysarmor/agent/agent.yaml"
	}
	writeJSON(writer, map[string]any{"enrollment_id": enrollment.ID, "token_expires_at": enrollment.ExpiresAt,
		"install_command": installCommand, "entrypoint_command": entrypoint, "script_url": scriptURL,
		"artifact": handler.mapDeployCommandArtifact(request, enrollment), "enrollment": handler.mapEnrollmentDocument(enrollment)})
}

func (handler *Handler) mapDeployCommandArtifact(request *http.Request, enrollment domainenrollment.Enrollment) deployCommandArtifact {
	if enrollment.ArtifactID == "" {
		return deployCommandArtifact{}
	}
	downloadURL := strings.TrimSpace(enrollment.ArtifactURL)
	if downloadURL == "" {
		downloadURL = handler.absoluteURL(request, "/api/v1/artifacts/"+url.PathEscape(enrollment.ArtifactID)+"/download")
	} else if enrollment.Profile != "linux-container" {
		downloadURL = rewritePackageDownloadURL(downloadURL, handler.packageDownloadBaseURL)
	}
	return deployCommandArtifact{ArtifactID: enrollment.ArtifactID, DownloadURL: downloadURL, SHA256: enrollment.ArtifactSHA256}
}

func (handler *Handler) absoluteURL(request *http.Request, targetPath string) string {
	if configured, err := url.Parse(strings.TrimSpace(handler.publicURL)); err == nil && configured.IsAbs() && configured.Host != "" {
		return strings.TrimRight(configured.String(), "/") + "/" + strings.TrimLeft(targetPath, "/")
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + targetPath
}

func (handler *Handler) DeployOptions(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requestContext, ok := handler.resolveRequest(writer, request)
	if !ok {
		return
	}
	result, err := handler.deployment.DeploymentOptions(request.Context(), requestContext)
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	writeJSON(writer, handler.mapDeployOptions(request, requestContext.Actor.TenantID.String(), result))
}

func (handler *Handler) mapDeployOptions(request *http.Request, tenantID string, result enrollmentapp.DeploymentOptionsResult) map[string]any {
	enrollments := make([]enrollmentViewDocument, 0, len(result.Enrollments))
	for _, value := range result.Enrollments {
		enrollments = append(enrollments, handler.mapEnrollmentView(value))
	}
	artifacts := make([]map[string]any, 0, len(result.Artifacts))
	for _, value := range result.Artifacts {
		downloadURL := value.DownloadURL
		if downloadURL == "" {
			downloadURL = handler.absoluteURL(request, "/api/v1/artifacts/"+url.PathEscape(value.ID)+"/download")
		} else {
			downloadURL = rewritePackageDownloadURL(downloadURL, handler.packageDownloadBaseURL)
		}
		artifacts = append(artifacts, map[string]any{"artifact_id": value.ID, "version": value.Version,
			"os": value.OS, "arch": value.Arch, "sha256": value.SHA256, "status": value.Status,
			"download_url": downloadURL, "created_at": value.CreatedAt})
	}
	return map[string]any{"tenant_id": tenantID, "gateway_addr": handler.deployGatewayAddress,
		"gateway_sni": handler.deployGatewayServerName, "supported_platforms": supportedDeployPlatforms(result.Artifacts),
		"artifacts": artifacts, "enrollments": enrollments}
}

func supportedDeployPlatforms(artifacts []domainenrollment.DeploymentArtifact) []map[string]string {
	result := []map[string]string{{"os": "linux", "arch": "amd64"}, {"os": "linux", "arch": "arm64"}}
	seen := map[string]bool{"linux/amd64": true, "linux/arm64": true}
	for _, artifact := range artifacts {
		key := artifact.OS + "/" + artifact.Arch
		if artifact.OS != "" && artifact.Arch != "" && !seen[key] {
			result = append(result, map[string]string{"os": artifact.OS, "arch": artifact.Arch})
			seen[key] = true
		}
	}
	return result
}

func rewritePackageDownloadURL(downloadURL, base string) string {
	base = strings.TrimSpace(base)
	parsed, err := url.Parse(downloadURL)
	if base == "" || err != nil || parsed.Path == "" {
		return downloadURL
	}
	return strings.TrimRight(base, "/") + "/" + path.Base(parsed.Path)
}
