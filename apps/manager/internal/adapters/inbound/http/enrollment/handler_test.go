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
			Labels: map[string]string{"env": "prod"}, Status: domainenrollment.StatusActive,
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
		"gateway_sni":"gateway.internal","profile":"linux-systemd","labels":{"env":"prod"},"ttl":"1h"
	}`))
	rec := httptest.NewRecorder()

	handler.Enrollments(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if service.command.TTL != time.Hour || service.request.Actor.Subject != "operator-a" {
		t.Fatalf("request=%#v command=%#v", service.request, service.command)
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
