package enrollment

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
	"google.golang.org/grpc"
)

func Revoke(ctx context.Context, enrollment sqlite.Enrollment, completionTokenHash string) (string, time.Time, error) {
	creds, err := tlsconfig.ClientCredentials(tlsconfig.ClientConfig{
		CAFile: enrollment.TLSCAPath, CertFile: enrollment.TLSCertPath, KeyFile: enrollment.TLSKeyPath, ServerName: enrollment.TLSServerName,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, normalizeGRPCAddress(enrollment.GatewayAddress), grpc.WithTransportCredentials(creds), grpc.WithBlock())
	if err != nil {
		return "", time.Time{}, fmt.Errorf("connect manager revocation service: %w", err)
	}
	defer conn.Close()
	response, err := controlplanev1.NewAgentControlPlaneServiceClient(conn).RevokeEnrollment(dialCtx, &controlplanev1.RevokeEnrollmentRequest{
		TenantId: enrollment.TenantID, AgentId: enrollment.AgentID, EnrollmentId: enrollment.EnrollmentID, CertificateSerial: enrollment.CertificateSerial,
		CompletionTokenHash: completionTokenHash,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("revoke enrollment certificate: %w", err)
	}
	revokedAt, err := time.Parse(time.RFC3339Nano, response.GetRevokedAt())
	completionRequired := strings.TrimSpace(completionTokenHash) != ""
	if err != nil || response.GetReceiptId() == "" || response.GetStatus() != "revoked" || response.GetCompletionRequired() != completionRequired {
		return "", time.Time{}, fmt.Errorf("manager revocation response is invalid")
	}
	return response.GetReceiptId(), revokedAt.UTC(), nil
}

func normalizeGRPCAddress(address string) string {
	address = strings.TrimPrefix(address, "http://")
	address = strings.TrimPrefix(address, "https://")
	return strings.TrimRight(address, "/")
}
