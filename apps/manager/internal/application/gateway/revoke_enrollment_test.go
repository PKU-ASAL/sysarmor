package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
)

func TestRevokeEnrollmentEnforcesProtocolMatrix(t *testing.T) {
	tests := []struct {
		name        string
		certificate domaingateway.Certificate
		request     domaingateway.RevokeEnrollment
	}{
		{"modern downgrade", domaingateway.Certificate{Protocol: "completion_v1"}, domaingateway.RevokeEnrollment{}},
		{"legacy upgrade", domaingateway.Certificate{Protocol: "legacy_mtls"}, domaingateway.RevokeEnrollment{CompletionTokenHash: strings.Repeat("a", 64)}},
		{"invalid token", domaingateway.Certificate{Protocol: "completion_v1"}, domaingateway.RevokeEnrollment{CompletionTokenHash: "bad"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &revocationRepositoryStub{certificate: canonicalCertificate(test.certificate)}
			_, err := NewRevokeEnrollmentService(repository).Revoke(context.Background(), canonicalRequest(test.request))
			if err == nil {
				t.Fatal("Revoke() error = nil")
			}
		})
	}
}

func TestRevokeEnrollmentDelegatesCanonicalRequest(t *testing.T) {
	repository := &revocationRepositoryStub{certificate: canonicalCertificate(domaingateway.Certificate{Protocol: "completion_v1"}), result: domaingateway.Revocation{ReceiptID: "receipt-a", RevokedAt: time.Unix(100, 0).UTC(), CompletionRequired: true}}
	request := canonicalRequest(domaingateway.RevokeEnrollment{EnrollmentID: "enroll-a", CertificateSerial: "42", CompletionTokenHash: strings.Repeat("a", 64)})
	result, err := NewRevokeEnrollmentService(repository).Revoke(context.Background(), request)
	if err != nil || result.ReceiptID != "receipt-a" || repository.request.CertificateSerial != "42" {
		t.Fatalf("result = %+v, request = %+v, err = %v", result, repository.request, err)
	}
}

func TestRevokeEnrollmentPropagatesRepositoryConflict(t *testing.T) {
	repository := &revocationRepositoryStub{certificate: canonicalCertificate(domaingateway.Certificate{Protocol: "legacy_mtls"}), err: errors.New("identity conflict")}
	_, err := NewRevokeEnrollmentService(repository).Revoke(context.Background(), canonicalRequest(domaingateway.RevokeEnrollment{}))
	if err == nil {
		t.Fatal("Revoke() error = nil")
	}
}

type revocationRepositoryStub struct {
	certificate domaingateway.Certificate
	result      domaingateway.Revocation
	request     domaingateway.RevokeEnrollment
	err         error
}

func (stub *revocationRepositoryStub) Certificate(context.Context, string, string) (domaingateway.Certificate, bool, error) {
	return stub.certificate, true, nil
}

func (stub *revocationRepositoryStub) Revoke(_ context.Context, request domaingateway.RevokeEnrollment) (domaingateway.Revocation, error) {
	stub.request = request
	return stub.result, stub.err
}

func canonicalCertificate(value domaingateway.Certificate) domaingateway.Certificate {
	value.TenantID, value.AgentID, value.EnrollmentID, value.Serial = "tenant-a", "agent-a", "enroll-a", "42"
	return value
}

func canonicalRequest(value domaingateway.RevokeEnrollment) domaingateway.RevokeEnrollment {
	value.TenantID, value.AgentID, value.PeerTenantID, value.PeerAgentID, value.PeerSerial = "tenant-a", "agent-a", "tenant-a", "agent-a", "42"
	return value
}
