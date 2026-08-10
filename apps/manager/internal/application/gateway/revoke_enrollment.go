package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

const (
	legacyMTLSProtocol = "legacy_mtls"
	completionProtocol = "completion_v1"
)

type RevokeEnrollmentService struct {
	repository ports.EnrollmentRevocationRepository
}

func NewRevokeEnrollmentService(repository ports.EnrollmentRevocationRepository) *RevokeEnrollmentService {
	return &RevokeEnrollmentService{repository: repository}
}

func (service *RevokeEnrollmentService) Revoke(ctx context.Context, request domaingateway.RevokeEnrollment) (domaingateway.Revocation, error) {
	if request.PeerTenantID == "" || request.PeerAgentID == "" || request.PeerSerial == "" {
		return domaingateway.Revocation{}, failure.New(failure.Unauthenticated, "mTLS agent identity is required")
	}
	if request.TenantID != request.PeerTenantID || request.AgentID != request.PeerAgentID {
		return domaingateway.Revocation{}, failure.New(failure.PermissionDenied, "certificate identity does not match revocation request")
	}
	certificate, found, err := service.repository.Certificate(ctx, request.PeerTenantID, request.PeerSerial)
	if err != nil {
		return domaingateway.Revocation{}, fmt.Errorf("read agent certificate: %w", err)
	}
	if !found || certificate.AgentID != request.PeerAgentID {
		return domaingateway.Revocation{}, failure.New(failure.PermissionDenied, "agent certificate is not registered")
	}
	if err := validateRevocationProtocol(certificate, request); err != nil {
		return domaingateway.Revocation{}, err
	}
	request.EnrollmentID = certificate.EnrollmentID
	request.CertificateSerial = certificate.Serial
	return service.repository.Revoke(ctx, request)
}

func validateRevocationProtocol(certificate domaingateway.Certificate, request domaingateway.RevokeEnrollment) error {
	protocol := strings.TrimSpace(certificate.Protocol)
	if protocol == "" {
		protocol = legacyMTLSProtocol
	}
	if request.CertificateSerial != "" && request.CertificateSerial != certificate.Serial {
		return failure.New(failure.PermissionDenied, "certificate identity does not match revocation request")
	}
	if request.EnrollmentID != "" && request.EnrollmentID != certificate.EnrollmentID {
		return failure.New(failure.PermissionDenied, "certificate enrollment identity mismatch")
	}
	if request.CompletionTokenHash == "" {
		if protocol != legacyMTLSProtocol {
			return failure.New(failure.PermissionDenied, "certificate does not allow legacy unenrollment")
		}
		return nil
	}
	if protocol != completionProtocol {
		return failure.New(failure.PermissionDenied, "certificate requires legacy unenrollment")
	}
	if !validSHA256(request.CompletionTokenHash) {
		return failure.New(failure.InvalidArgument, "completion token hash is invalid")
	}
	return nil
}

func validSHA256(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return false
		}
	}
	return true
}
