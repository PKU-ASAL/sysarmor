package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestDeployAgentCommandUsesEnrollmentCreateService(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	create := &createServiceStub{result: enrollmentapp.CreateEnrollmentResult{
		Enrollment: domainenrollment.Enrollment{ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a",
			Profile: "linux-systemd", ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a",
			CreatedAt: time.Unix(100, 0).UTC(), ExpiresAt: time.Unix(3700, 0).UTC()},
		BootstrapTicket: "bootstrap-ticket",
	}}
	handler := NewHandler(Options{Create: create, Resolve: fixedRequestResolver(tenantID),
		PublicURL: "https://manager.example/base"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ui/deploy/agent-command", strings.NewReader(`{
		"tenant_id":"tenant-a","agent_id":"agent-a","gateway_addr":"gateway:9444",
		"channel":"linux-systemd-missing","artifact_id":"artifact-a","ttl":"1h"
	}`))
	recorder := httptest.NewRecorder()

	handler.DeployAgentCommand(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !create.command.FallbackToArtifact || create.command.Channel != "linux-systemd-missing" {
		t.Fatalf("command=%#v", create.command)
	}
	var response struct {
		EnrollmentID   string `json:"enrollment_id"`
		InstallCommand string `json:"install_command"`
		ScriptURL      string `json:"script_url"`
		Artifact       struct {
			ArtifactID  string `json:"artifact_id"`
			DownloadURL string `json:"download_url"`
			SHA256      string `json:"sha256"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.EnrollmentID != "enroll-a" || response.ScriptURL != "https://manager.example/base/api/v1/agent-install.sh?ticket=bootstrap-ticket" ||
		!strings.Contains(response.InstallCommand, "| sudo bash") || response.Artifact.ArtifactID != "artifact-a" ||
		response.Artifact.DownloadURL != "https://manager.example/base/api/v1/artifacts/artifact-a/download" || response.Artifact.SHA256 != "sha256-a" {
		t.Fatalf("response=%#v", response)
	}
}

func TestDeployOptionsUsesTenantScopedApplicationQuery(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	query := &deploymentQueryStub{result: enrollmentapp.DeploymentOptionsResult{
		Enrollments: []enrollmentapp.EnrollmentView{{Enrollment: domainenrollment.Enrollment{
			ID: "enroll-a", TenantID: tenantID, TokenHash: "secret", AgentID: "agent-a",
		}}},
		Artifacts: []domainenrollment.DeploymentArtifact{{ID: "artifact-a", Version: "1.0.0", OS: "linux",
			Arch: "amd64", SHA256: "sha256-a", Status: "active", DownloadURL: "https://packages/artifact-a.tar.gz"}},
	}}
	handler := NewHandler(Options{DeploymentQuery: query, Resolve: fixedRequestResolver(tenantID),
		DeployGatewayAddress: "gateway:9444", DeployGatewayServerName: "gateway.internal"})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/ui/deploy/options", nil)
	recorder := httptest.NewRecorder()

	handler.DeployOptions(recorder, request)
	if recorder.Code != http.StatusOK || query.request.Actor.TenantID != tenantID {
		t.Fatalf("status=%d request=%#v body=%s", recorder.Code, query.request, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, want := range []string{`"gateway_addr":"gateway:9444"`, `"gateway_sni":"gateway.internal"`,
		`"artifact_id":"artifact-a"`, `"enrollment_id":"enroll-a"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "token_hash") {
		t.Fatalf("response leaked enrollment secret: %s", body)
	}
}

func TestEnrollmentDocumentRewritesOnlySystemdPackageURL(t *testing.T) {
	handler := NewHandler(Options{PackageDownloadBaseURL: "https://downloads.example/releases"})
	for _, test := range []struct{ profile, want string }{
		{"linux-systemd", "https://downloads.example/releases/agent.tar.gz"},
		{"linux-container", "http://packages.internal/agent.tar.gz"},
	} {
		document := handler.mapEnrollmentDocument(domainenrollment.Enrollment{
			Profile: test.profile, ArtifactURL: "http://packages.internal/agent.tar.gz",
		})
		if document.ArtifactURL != test.want {
			t.Fatalf("profile=%q artifact URL=%q want=%q", test.profile, document.ArtifactURL, test.want)
		}
	}
}

type deploymentQueryStub struct {
	request managerapp.RequestContext
	result  enrollmentapp.DeploymentOptionsResult
	err     error
}

func (stub *deploymentQueryStub) DeploymentOptions(_ context.Context, request managerapp.RequestContext) (enrollmentapp.DeploymentOptionsResult, error) {
	stub.request = request
	return stub.result, stub.err
}
