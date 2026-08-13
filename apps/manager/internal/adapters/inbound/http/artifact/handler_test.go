package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestArtifactsListUsesAuthenticatedTenantAndPublicJSONShape(t *testing.T) {
	service := &artifactServiceStub{artifacts: []domainartifact.Artifact{{
		ID: "artifact-a", TenantID: tenant.ID("tenant-a"), Name: "agent", Kind: "agent", Version: "1.0.0",
		SHA256: "sha256-a", Status: domainartifact.StatusActive, CreatedAt: time.Unix(100, 0).UTC(),
		UpdatedAt: time.Unix(100, 0).UTC(),
	}}}
	handler := NewHandler(Options{Service: service, Resolve: artifactResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Artifacts(recorder, httptest.NewRequest(http.MethodGet,
		"/api/v1/artifacts?tenant_id=tenant-b&kind=agent&status=active", nil))

	if recorder.Code != http.StatusOK || service.request.Actor.TenantID != tenant.ID("tenant-a") {
		t.Fatalf("status=%d tenant=%q body=%s", recorder.Code, service.request.Actor.TenantID, recorder.Body.String())
	}
	var response struct {
		Artifacts []map[string]any `json:"artifacts"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Artifacts) != 1 || response.Artifacts[0]["artifact_id"] != "artifact-a" || response.Artifacts[0]["ID"] != nil {
		t.Fatalf("response=%s", recorder.Body.String())
	}
}

func TestCreateChannelIgnoresBodyTenantAndActor(t *testing.T) {
	service := &artifactServiceStub{channel: domainartifact.Channel{
		TenantID: tenant.ID("tenant-a"), Name: "stable", ArtifactID: "artifact-a",
	}}
	handler := NewHandler(Options{Service: service, Resolve: artifactResolver(t)})
	body := bytes.NewBufferString(`{"tenant_id":"tenant-b","channel":"stable","artifact_id":"artifact-a","actor":"attacker"}`)
	recorder := httptest.NewRecorder()
	handler.Channels(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/channels", body))

	if recorder.Code != http.StatusOK || service.request.Actor.Subject != "operator-a" {
		t.Fatalf("status=%d request=%+v body=%s", recorder.Code, service.request, recorder.Body.String())
	}
	if service.channelCommand.Name != "stable" || service.channelCommand.ArtifactID != "artifact-a" {
		t.Fatalf("command=%+v", service.channelCommand)
	}
}

func TestUploadArtifactMapsMultipartAndAuthenticatedIdentity(t *testing.T) {
	service := &artifactServiceStub{artifact: domainartifact.Artifact{
		ID: "artifact-a", TenantID: tenant.ID("tenant-a"), Name: "bundle", Kind: "bundle", Version: "1.0.0",
		SHA256: "sha256-a", Status: domainartifact.StatusDraft,
	}}
	handler := NewHandler(Options{Service: service, Resolve: artifactResolver(t)})
	var body bytes.Buffer
	multipartWriter := multipart.NewWriter(&body)
	for key, value := range map[string]string{"tenant_id": "tenant-b", "actor": "attacker", "name": "bundle",
		"kind": "bundle", "version": "1.0.0", "status": "draft"} {
		if err := multipartWriter.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	file, err := multipartWriter.CreateFormFile("file", "bundle.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("archive")); err != nil {
		t.Fatal(err)
	}
	if err := multipartWriter.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://manager.example/api/v1/artifacts", &body)
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	recorder := httptest.NewRecorder()
	handler.Artifacts(recorder, request)

	if recorder.Code != http.StatusOK || service.request.Actor.TenantID != tenant.ID("tenant-a") {
		t.Fatalf("status=%d request=%+v body=%s", recorder.Code, service.request, recorder.Body.String())
	}
	if service.uploadCommand.Name != "bundle" || service.uploadCommand.Filename != "bundle.tar.gz" {
		t.Fatalf("command=%+v", service.uploadCommand)
	}
	var response struct {
		DownloadURL string `json:"download_url"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DownloadURL != "http://manager.example/api/v1/artifacts/artifact-a/download" {
		t.Fatalf("download_url=%q", response.DownloadURL)
	}
}

func TestArtifactStatusRouteUsesAuthenticatedTenant(t *testing.T) {
	service := &artifactServiceStub{artifact: domainartifact.Artifact{ID: "artifact-a", TenantID: tenant.ID("tenant-a")}}
	handler := NewHandler(Options{Service: service, Resolve: artifactResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Artifact(recorder, httptest.NewRequest(http.MethodPost,
		"/api/v1/artifacts/artifact-a/activate?tenant_id=tenant-b", nil))

	if recorder.Code != http.StatusOK || service.request.Actor.TenantID != tenant.ID("tenant-a") {
		t.Fatalf("status=%d request=%+v body=%s", recorder.Code, service.request, recorder.Body.String())
	}
	if service.statusCommand.ArtifactID != "artifact-a" || service.statusCommand.Status != domainartifact.StatusActive {
		t.Fatalf("command=%+v", service.statusCommand)
	}
}

func TestDownloadArtifactServesArchivedContent(t *testing.T) {
	service := &artifactServiceStub{artifact: domainartifact.Artifact{ID: "artifact-a", TenantID: tenant.ID("tenant-a"),
		SHA256: "sha256-a", Status: domainartifact.StatusActive, StoragePath: "/archive/artifact-a.tar.gz"}}
	content := &artifactContentStub{value: ports.ArchivedContent{Content: readSeekCloser{ReadSeeker: bytes.NewReader([]byte("archive"))},
		Name: "artifact-a.tar.gz", Size: 7, ModTime: time.Unix(100, 0).UTC()}}
	handler := NewHandler(Options{Service: service, Content: content, Resolve: artifactResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Artifact(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/artifact-a/download", nil))

	if recorder.Code != http.StatusOK || recorder.Body.String() != "archive" || content.path != service.artifact.StoragePath {
		t.Fatalf("status=%d body=%q path=%q", recorder.Code, recorder.Body.String(), content.path)
	}
	if recorder.Header().Get("X-SysArmor-Artifact-ID") != "artifact-a" ||
		recorder.Header().Get("X-SysArmor-Artifact-SHA256") != "sha256-a" {
		t.Fatalf("headers=%v", recorder.Header())
	}
}

func TestDownloadArtifactHidesRevokedArtifact(t *testing.T) {
	service := &artifactServiceStub{artifact: domainartifact.Artifact{ID: "artifact-a", TenantID: tenant.ID("tenant-a"),
		Status: domainartifact.StatusRevoked, StoragePath: "/archive/artifact-a.tar.gz"}}
	content := &artifactContentStub{}
	handler := NewHandler(Options{Service: service, Content: content, Resolve: artifactResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Artifact(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/artifact-a/download", nil))

	if recorder.Code != http.StatusNotFound || content.path != "" {
		t.Fatalf("status=%d path=%q", recorder.Code, content.path)
	}
}

func TestDownloadExternalArtifactRedirectsToConfiguredBase(t *testing.T) {
	t.Setenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL", "https://mirror.example/releases")
	service := &artifactServiceStub{artifact: domainartifact.Artifact{ID: "artifact-a", TenantID: tenant.ID("tenant-a"),
		Status: domainartifact.StatusActive, Metadata: map[string]string{
			"download_url": "https://index.example/builds/sysarmor-agent.tar.gz",
		}}}
	handler := NewHandler(Options{Service: service, Resolve: artifactResolver(t)})
	recorder := httptest.NewRecorder()
	handler.Artifact(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/artifact-a/download", nil))

	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "https://mirror.example/releases/sysarmor-agent.tar.gz" {
		t.Fatalf("status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}

type artifactServiceStub struct {
	request        managerapp.RequestContext
	artifacts      []domainartifact.Artifact
	artifact       domainartifact.Artifact
	channel        domainartifact.Channel
	channelCommand artifactapp.SetChannelCommand
	uploadCommand  artifactapp.UploadCommand
	statusCommand  artifactapp.ChangeStatusCommand
}

func (stub *artifactServiceStub) Upload(_ context.Context, request managerapp.RequestContext, command artifactapp.UploadCommand) (domainartifact.Artifact, error) {
	stub.request, stub.uploadCommand = request, command
	return stub.artifact, nil
}

func (stub *artifactServiceStub) ChangeStatus(_ context.Context, request managerapp.RequestContext, command artifactapp.ChangeStatusCommand) (domainartifact.Artifact, error) {
	stub.request, stub.statusCommand = request, command
	return stub.artifact, nil
}

func (stub *artifactServiceStub) SetChannel(_ context.Context, request managerapp.RequestContext, command artifactapp.SetChannelCommand) (domainartifact.Channel, error) {
	stub.request, stub.channelCommand = request, command
	return stub.channel, nil
}

func (stub *artifactServiceStub) ListArtifacts(_ context.Context, request managerapp.RequestContext, _ artifactapp.ArtifactQuery) ([]domainartifact.Artifact, error) {
	stub.request = request
	return stub.artifacts, nil
}

func (stub *artifactServiceStub) GetArtifact(_ context.Context, request managerapp.RequestContext, _ string) (domainartifact.Artifact, error) {
	stub.request = request
	return stub.artifact, nil
}

func (stub *artifactServiceStub) ListChannels(context.Context, managerapp.RequestContext) ([]domainartifact.Channel, error) {
	return nil, nil
}

func (stub *artifactServiceStub) GetChannel(context.Context, managerapp.RequestContext, string) (domainartifact.Channel, error) {
	return stub.channel, nil
}

func artifactResolver(t *testing.T) RequestContextResolver {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{Subject: "operator-a", TenantID: tenantID,
			Roles: tenant.NewRoleSet(tenant.RoleOperator)}}, nil
	}
}

type artifactContentStub struct {
	path  string
	value ports.ArchivedContent
}

func (stub *artifactContentStub) Open(_ context.Context, path string) (ports.ArchivedContent, error) {
	stub.path = path
	return stub.value, nil
}

type readSeekCloser struct{ io.ReadSeeker }

func (readSeekCloser) Close() error { return nil }
