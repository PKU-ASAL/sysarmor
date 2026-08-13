package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func TestIssuerBindsCertificateToEnrollmentIdentity(t *testing.T) {
	caPEM, keyPEM := testCertificateAuthority(t)
	issuer, err := NewIssuer(caPEM, keyPEM, "sysarmor.test")
	if err != nil {
		t.Fatal(err)
	}
	csr := testCertificateRequest(t)
	tenantID, _ := tenant.NewID("tenant-a")
	value := domainenrollment.Enrollment{ID: "enroll-a", TenantID: tenantID, AgentID: "agent-a"}

	issued, err := issuer.Issue(context.Background(), value, csr)
	if err != nil {
		t.Fatal(err)
	}
	if issued.KeySHA256 == "" || issued.CAPEM != string(caPEM) {
		t.Fatalf("issuance = %#v", issued)
	}
	block, _ := pem.Decode([]byte(issued.Certificate.CertificatePEM))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := certificate.URIs[0].String(); got != "spiffe://sysarmor.test/tenant/tenant-a/agent/agent-a" {
		t.Fatalf("URI SAN = %q", got)
	}
}

func TestNewIssuerAcceptsPKCS8RSAKey(t *testing.T) {
	caPEM, keyPEM := testCertificateAuthority(t)
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewIssuer(caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "sysarmor.test"); err != nil {
		t.Fatalf("NewIssuer() error = %v", err)
	}
}

func TestNewIssuerRejectsPKCS8NonRSAKey(t *testing.T) {
	caPEM, _ := testCertificateAuthority(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewIssuer(caPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "sysarmor.test")
	if err == nil || !strings.Contains(err.Error(), "must be RSA") {
		t.Fatalf("NewIssuer() error = %v, want RSA type error", err)
	}
}

func testCertificateAuthority(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func testCertificateRequest(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
