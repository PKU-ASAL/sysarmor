package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
	"google.golang.org/grpc"
)

type revocationContractServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	completionRequired atomic.Bool
}

func (s *revocationContractServer) RevokeEnrollment(context.Context, *controlplanev1.RevokeEnrollmentRequest) (*controlplanev1.RevokeEnrollmentResponse, error) {
	return &controlplanev1.RevokeEnrollmentResponse{
		Status: "revoked", RevokedAt: time.Unix(100, 0).UTC().Format(time.RFC3339Nano),
		ReceiptId: "receipt-a", CompletionRequired: s.completionRequired.Load(),
	}, nil
}

func TestRevokeEnrollmentOnlineValidatesCompletionContract(t *testing.T) {
	enrollment, serverOpt := revocationClientEnrollment(t)
	server := &revocationContractServer{}
	grpcServer := grpc.NewServer(serverOpt)
	controlplanev1.RegisterAgentControlPlaneServiceServer(grpcServer, server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()
	enrollment.GatewayAddress = listener.Addr().String()

	for _, test := range []struct {
		name, tokenHash string
		managerRequires bool
		wantError       bool
	}{
		{name: "legacy", managerRequires: false},
		{name: "legacy mismatch", managerRequires: true, wantError: true},
		{name: "completion", tokenHash: strings.Repeat("a", 64), managerRequires: true},
		{name: "completion mismatch", tokenHash: strings.Repeat("a", 64), managerRequires: false, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server.completionRequired.Store(test.managerRequires)
			receipt, _, err := revokeEnrollmentOnline(t.Context(), enrollment, test.tokenHash)
			if (err != nil) != test.wantError || (!test.wantError && receipt != "receipt-a") {
				t.Fatalf("receipt=%q err=%v wantError=%t", receipt, err, test.wantError)
			}
		})
	}
}

func revocationClientEnrollment(t *testing.T) (localstore.Enrollment, grpc.ServerOption) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey := signedRevocationTestCertificate(t, ca, caKey, 2, "localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert, clientKey := signedRevocationTestCertificate(t, ca, caKey, 3, "agent", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	caPath := writeRevocationPEM(t, dir, "ca.pem", "CERTIFICATE", ca.Raw)
	serverCertPath := writeRevocationPEM(t, dir, "server.pem", "CERTIFICATE", serverCert.Raw)
	serverKeyPath := writeRevocationECKey(t, dir, "server-key.pem", serverKey)
	clientCertPath := writeRevocationPEM(t, dir, "agent.pem", "CERTIFICATE", clientCert.Raw)
	clientKeyPath := writeRevocationECKey(t, dir, "agent-key.pem", clientKey)
	serverOpt, err := tlsconfig.MTLSServerOption(serverCertPath, serverKeyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	return localstore.Enrollment{TenantID: "tenant-a", AgentID: "agent-a", TLSCAPath: caPath,
		TLSCertPath: clientCertPath, TLSKeyPath: clientKeyPath, TLSServerName: "localhost"}, serverOpt
}

func signedRevocationTestCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, commonName string, usage []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: usage}
	if commonName == "localhost" {
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func writeRevocationPEM(t *testing.T, dir, name, blockType string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRevocationECKey(t *testing.T, dir, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	raw, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return writeRevocationPEM(t, dir, name, "EC PRIVATE KEY", raw)
}
