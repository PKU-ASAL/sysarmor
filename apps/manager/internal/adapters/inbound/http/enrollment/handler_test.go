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
	handler := NewHandler(service)
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

type issueServiceStub struct {
	command enrollmentapp.IssueCertificateCommand
	result  enrollmentapp.IssueCertificateResult
	err     error
}

func (stub *issueServiceStub) Execute(_ context.Context, command enrollmentapp.IssueCertificateCommand) (enrollmentapp.IssueCertificateResult, error) {
	stub.command = command
	return stub.result, stub.err
}
