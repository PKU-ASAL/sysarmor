package enrollment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

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
	handler := NewHandler(service, nil)
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
	handler := NewHandler(nil, service)
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
