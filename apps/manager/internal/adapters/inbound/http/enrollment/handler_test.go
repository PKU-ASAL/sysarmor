package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestCreateEnrollmentPreservesPublishedResponse(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	service := &createServiceStub{result: enrollmentapp.CreateEnrollmentResult{
		Enrollment: domainenrollment.Enrollment{
			ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a", HostID: "host-a",
			TokenPreview: "enr_...oken", BootstrapTokenPreview: "enr_...boot",
			GatewayAddress: "gateway:9444", GatewayServerName: "gateway.internal", Profile: "linux-systemd",
			Channel: "linux-systemd-stable", ArtifactID: "artifact-a", ArtifactSHA256: "sha256-a",
			ArtifactURL: "https://packages.example/agent.tar.gz",
			Labels:      map[string]string{"env": "prod"}, Status: domainenrollment.StatusActive,
			BootstrapFetchedAt: time.Unix(110, 0).UTC(), UsedAt: time.Unix(120, 0).UTC(), IssuedAt: time.Unix(130, 0).UTC(),
			Issuance: domainenrollment.Issuance{Certificate: domainenrollment.Certificate{
				SerialNumber: "42", NotAfter: time.Unix(500, 0).UTC(), CertificatePEM: "secret-certificate",
			}},
			CreatedAt: time.Unix(100, 0).UTC(), ExpiresAt: time.Unix(3700, 0).UTC(), CreatedBy: "operator-a",
		},
		Token: "enrollment-token", BootstrapTicket: "bootstrap-ticket",
	}}
	handler := NewHandler(Options{Create: service, Resolve: func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{
			Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
		}}, nil
	}})
	req := httptest.NewRequest(http.MethodPost, "http://manager.test/api/v1/enrollments", strings.NewReader(`{
		"tenant_id":"tenant-a","agent_id":"agent-a","host_id":"host-a","gateway_addr":"gateway:9444",
		"gateway_sni":"gateway.internal","profile":"linux-systemd","channel":"linux-systemd-stable",
		"artifact_id":"artifact-a","artifact_url":"https://ignored.example/agent.tar.gz","labels":{"env":"prod"},"ttl":"1h"
	}`))
	rec := httptest.NewRecorder()

	handler.Enrollments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if service.command.TTL != time.Hour || service.request.Actor.Subject != "operator-a" {
		t.Fatalf("request=%#v command=%#v", service.request, service.command)
	}
	if service.command.Channel != "linux-systemd-stable" || service.command.ArtifactID != "artifact-a" ||
		service.command.ArtifactURL != "https://ignored.example/agent.tar.gz" {
		t.Fatalf("material command=%#v", service.command)
	}
	if strings.Contains(rec.Body.String(), "token_hash") || strings.Contains(rec.Body.String(), "bootstrap_token_hash") {
		t.Fatalf("response leaked token hash: %s", rec.Body.String())
	}
	var response struct {
		Token      string `json:"token"`
		InstallURL string `json:"install_url"`
		Enrollment struct {
			EnrollmentID string `json:"enrollment_id"`
			TenantID     string `json:"tenant_id"`
		} `json:"enrollment"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Token != "enrollment-token" || response.Enrollment.EnrollmentID != "enroll-a" || response.Enrollment.TenantID != "tenant-a" {
		t.Fatalf("response=%#v", response)
	}
	if !strings.Contains(rec.Body.String(), `"channel":"linux-systemd-stable"`) ||
		!strings.Contains(rec.Body.String(), `"artifact_sha256":"sha256-a"`) ||
		!strings.Contains(rec.Body.String(), `"bootstrap_fetched_at":"1970-01-01T00:01:50Z"`) ||
		!strings.Contains(rec.Body.String(), `"used_at":"1970-01-01T00:02:00Z"`) ||
		!strings.Contains(rec.Body.String(), `"issued_serial_number":"42"`) ||
		!strings.Contains(rec.Body.String(), `"issued_not_after":"1970-01-01T00:08:20Z"`) ||
		!strings.Contains(rec.Body.String(), `"issued_at":"1970-01-01T00:02:10Z"`) {
		t.Fatalf("material response=%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-certificate") {
		t.Fatalf("response leaked certificate: %s", rec.Body.String())
	}
	if response.InstallURL != "http://manager.test/api/v1/agent-install.sh?ticket=bootstrap-ticket" {
		t.Fatalf("install URL=%q", response.InstallURL)
	}
}

func TestCreateEnrollmentUsesConfiguredPublicURL(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	service := &createServiceStub{result: enrollmentapp.CreateEnrollmentResult{
		Enrollment: domainenrollment.Enrollment{ID: "enroll-a", TenantID: tenantID},
		Token:      "enrollment-token", BootstrapTicket: "bootstrap-ticket",
	}}
	handler := NewHandler(Options{
		Create: service, Resolve: fixedRequestResolver(tenantID), PublicURL: "https://manager.public.example/base/",
	})
	req := httptest.NewRequest(http.MethodPost, "http://manager.internal/api/v1/enrollments", strings.NewReader(`{
		"tenant_id":"tenant-a","agent_id":"agent-a","gateway_addr":"gateway:9444"
	}`))
	rec := httptest.NewRecorder()

	handler.Enrollments(rec, req)
	var response struct {
		InstallURL string `json:"install_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.InstallURL != "https://manager.public.example/base/api/v1/agent-install.sh?ticket=bootstrap-ticket" {
		t.Fatalf("install URL=%q", response.InstallURL)
	}
}

func TestListEnrollmentsProjectsUnenrollmentWithoutSecrets(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	record, err := domainenrollment.NewPendingUnenrollment(domainenrollment.UnenrollmentIdentity{
		TenantID: tenantID, AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42",
	}, "secret-receipt", "secret-token-hash", time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	query := &queryServiceStub{result: enrollmentapp.ListEnrollmentsResult{Enrollments: []enrollmentapp.EnrollmentView{{
		Enrollment: domainenrollment.Enrollment{ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a",
			TokenPreview: "enr_...oken", Status: domainenrollment.StatusIssued},
		Unenrollment: record, HasUnenrollment: true,
	}}}}
	handler := NewHandler(Options{Query: query, Resolve: fixedRequestResolver(tenantID)})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enrollments?status=issued", nil)
	rec := httptest.NewRecorder()

	handler.Enrollments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if query.query.Status != domainenrollment.StatusIssued || query.request.Actor.TenantID != tenantID {
		t.Fatalf("request=%#v query=%#v", query.request, query.query)
	}
	body := rec.Body.String()
	for _, secret := range []string{"secret-receipt", "secret-token-hash", "completion_token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("response leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"unenrollment_status":"revoked_endpoint_pending"`) ||
		!strings.Contains(body, `"enrollment_id":"enroll-a"`) {
		t.Fatalf("body=%s", body)
	}
}

func TestInstallRedeemsTicketAndReturnsNoStoreScript(t *testing.T) {
	tenantID, _ := tenant.NewID("tenant-a")
	bootstrap := &bootstrapServiceStub{result: enrollmentapp.RedeemBootstrapResult{
		Enrollment: domainenrollment.Enrollment{ID: "enroll-a", TenantID: tenantID}, Token: "rotated-token",
	}}
	renderer := &installScriptRendererStub{script: "#!/usr/bin/env bash\necho install\n"}
	handler := NewHandler(Options{Bootstrap: bootstrap, InstallScript: renderer})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent-install.sh?ticket=bootstrap-secret", nil)
	rec := httptest.NewRecorder()

	handler.Install(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("Content-Type") != "text/x-shellscript; charset=utf-8" {
		t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if bootstrap.command.TicketHash == "" || bootstrap.command.TicketHash == "bootstrap-secret" {
		t.Fatalf("ticket hash=%q", bootstrap.command.TicketHash)
	}
	if renderer.enrollment.ID != "enroll-a" || renderer.token != "rotated-token" || rec.Body.String() != renderer.script {
		t.Fatalf("renderer enrollment=%#v token=%q body=%q", renderer.enrollment, renderer.token, rec.Body.String())
	}
}

func TestArtifactAuthorizesTokenAndServesBoundFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.tar.gz")
	if err := os.WriteFile(path, []byte("artifact-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := &artifactServiceStub{result: enrollmentapp.AuthorizeArtifactResult{
		Artifact: domainenrollment.InstallArtifact{ID: "artifact-a", SHA256: "sha256-a", Status: "active", StoragePath: path},
	}}
	handler := NewHandler(Options{Artifact: service, ArtifactDir: directory})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/enrollment-artifact", nil)
	req.Header.Set("Authorization", "Enrollment enrollment-secret")
	rec := httptest.NewRecorder()

	handler.Artifact(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "artifact-bytes" ||
		rec.Header().Get("X-SysArmor-Artifact-ID") != "artifact-a" ||
		rec.Header().Get("X-SysArmor-Artifact-SHA256") != "sha256-a" {
		t.Fatalf("status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
	if service.command.TokenHash == "" || service.command.TokenHash == "enrollment-secret" {
		t.Fatalf("token hash=%q", service.command.TokenHash)
	}
}

func TestCertificatePreservesPublishedResponse(t *testing.T) {
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	service := &issueServiceStub{result: enrollmentapp.IssueCertificateResult{
		Enrollment: domainenrollment.Enrollment{
			ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a",
			GatewayAddress: "gateway:9444", GatewayServerName: "gateway.internal",
			Issuance: domainenrollment.Issuance{CAPEM: "ca", Certificate: domainenrollment.Certificate{
				SerialNumber: "42", CertificatePEM: "certificate", NotAfter: time.Unix(500, 0).UTC(),
			}},
		},
	}}
	handler := NewHandler(Options{Issue: service})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-certificate", strings.NewReader(`{"token":"secret","csr":"csr"}`))
	rec := httptest.NewRecorder()

	handler.Certificate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if service.command.TokenHash == "secret" || service.command.TokenHash == "" {
		t.Fatalf("token hash = %q", service.command.TokenHash)
	}
	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"schema_version": "sysarmor.enrollment/v2", "tenant_id": "tenant-a", "agent_id": "agent-a",
		"enrollment_id": "enroll-a", "gateway_address": "gateway:9444", "gateway_server_name": "gateway.internal",
		"certificate_pem": "certificate", "ca_pem": "ca", "serial_number": "42",
	} {
		if response[key] != want {
			t.Fatalf("%s=%v want=%q", key, response[key], want)
		}
	}
}

func TestCompletionHashesTokenAndPreservesResponse(t *testing.T) {
	record := pendingHTTPUnenrollment(t)
	service := &completionServiceStub{result: enrollmentapp.CompleteUnenrollmentResult{Unenrollment: record}}
	handler := NewHandler(Options{Completion: service})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/unenrollment-completions", strings.NewReader(`{
		"schema_version":"sysarmor.unenrollment-completion/v1","tenant_id":"tenant-a","agent_id":"agent-a",
		"enrollment_id":"enroll-a","certificate_serial":"42","revocation_receipt":"receipt-a","completion_token":"secret"
	}`))
	rec := httptest.NewRecorder()

	handler.Completion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if service.command.TokenHash == "secret" || service.command.TokenHash == "" {
		t.Fatalf("completion token hash = %q", service.command.TokenHash)
	}
	if !strings.Contains(rec.Body.String(), `"status":"revoked_endpoint_pending"`) {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

type issueServiceStub struct {
	command enrollmentapp.IssueCertificateCommand
	result  enrollmentapp.IssueCertificateResult
	err     error
}

type createServiceStub struct {
	request managerapp.RequestContext
	command enrollmentapp.CreateEnrollmentCommand
	result  enrollmentapp.CreateEnrollmentResult
	err     error
}

type queryServiceStub struct {
	request managerapp.RequestContext
	query   enrollmentapp.ListEnrollmentsQuery
	result  enrollmentapp.ListEnrollmentsResult
	err     error
}

type bootstrapServiceStub struct {
	command enrollmentapp.RedeemBootstrapCommand
	result  enrollmentapp.RedeemBootstrapResult
	err     error
}

type artifactServiceStub struct {
	command enrollmentapp.AuthorizeArtifactCommand
	result  enrollmentapp.AuthorizeArtifactResult
	err     error
}

func (stub *artifactServiceStub) Authorize(_ context.Context, command enrollmentapp.AuthorizeArtifactCommand) (enrollmentapp.AuthorizeArtifactResult, error) {
	stub.command = command
	return stub.result, stub.err
}

func (stub *bootstrapServiceStub) Redeem(_ context.Context, command enrollmentapp.RedeemBootstrapCommand) (enrollmentapp.RedeemBootstrapResult, error) {
	stub.command = command
	return stub.result, stub.err
}

type installScriptRendererStub struct {
	enrollment domainenrollment.Enrollment
	token      string
	script     string
	err        error
}

func (stub *installScriptRendererStub) Render(_ *http.Request, enrollment domainenrollment.Enrollment, token string) (string, error) {
	stub.enrollment, stub.token = enrollment, token
	return stub.script, stub.err
}

func (stub *queryServiceStub) List(_ context.Context, request managerapp.RequestContext, query enrollmentapp.ListEnrollmentsQuery) (enrollmentapp.ListEnrollmentsResult, error) {
	stub.request, stub.query = request, query
	return stub.result, stub.err
}

func (stub *createServiceStub) Execute(_ context.Context, request managerapp.RequestContext, command enrollmentapp.CreateEnrollmentCommand) (enrollmentapp.CreateEnrollmentResult, error) {
	stub.request, stub.command = request, command
	return stub.result, stub.err
}

func (stub *issueServiceStub) Execute(_ context.Context, command enrollmentapp.IssueCertificateCommand) (enrollmentapp.IssueCertificateResult, error) {
	stub.command = command
	return stub.result, stub.err
}

type completionServiceStub struct {
	command enrollmentapp.CompleteUnenrollmentCommand
	result  enrollmentapp.CompleteUnenrollmentResult
	err     error
}

func (stub *completionServiceStub) Execute(_ context.Context, command enrollmentapp.CompleteUnenrollmentCommand) (enrollmentapp.CompleteUnenrollmentResult, error) {
	stub.command = command
	return stub.result, stub.err
}

func pendingHTTPUnenrollment(t *testing.T) domainenrollment.Unenrollment {
	t.Helper()
	tenantID, err := tenant.NewID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := domainenrollment.NewPendingUnenrollment(domainenrollment.UnenrollmentIdentity{
		TenantID: tenantID, AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42",
	}, "receipt-a", "token-hash", time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func fixedRequestResolver(tenantID tenant.ID) RequestContextResolver {
	return func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{Actor: tenant.Actor{
			Subject: "operator-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleOperator),
		}}, nil
	}
}
