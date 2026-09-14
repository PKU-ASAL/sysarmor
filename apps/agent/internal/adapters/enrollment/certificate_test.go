package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentCSRDoesNotClaimManagerIdentity(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM, err := createEnrollmentCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "" || csr.CheckSignature() != nil {
		t.Fatalf("invalid CSR: %+v", csr.Subject)
	}
}

func TestPendingEnrollmentKeyIsReusedForToken(t *testing.T) {
	statePath := t.TempDir()
	first, firstPEM, firstPath, err := loadOrCreatePendingEnrollmentKey(statePath, "enr_secret")
	if err != nil {
		t.Fatal(err)
	}
	second, secondPEM, secondPath, err := loadOrCreatePendingEnrollmentKey(statePath, "enr_secret")
	if err != nil {
		t.Fatal(err)
	}
	if !first.PublicKey.Equal(&second.PublicKey) || string(firstPEM) != string(secondPEM) || firstPath != secondPath {
		t.Fatal("pending enrollment key was not reused")
	}
	if info, err := os.Stat(firstPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pending key mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestRemovePendingEnrollmentKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pending-key.pem")
	if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemovePendingKey(path); err != nil {
		t.Fatalf("RemovePendingKey() error = %v", err)
	}
	if err := RemovePendingKey(path); err != nil {
		t.Fatalf("RemovePendingKey() missing file error = %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pending key still exists: %v", err)
	}
}

func TestValidateEnrollmentCertificateRejectsWrongSubject(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tenant_id:other,agent_id:other"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	certDER, _ := x509.CreateCertificate(rand.Reader, certTemplate, ca, &key.PublicKey, caKey)
	response := Certificate{TenantID: "tenant-a", AgentID: "agent-a", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})), CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))}
	if err := validateEnrollmentCertificate(response, key); err == nil {
		t.Fatal("certificate with wrong subject accepted")
	}
}

func TestWriteEnrollmentCredentialsProtectsPrivateKey(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state")
	paths, created, err := WriteCredentials(statePath, Certificate{
		EnrollmentID: "enr-a", CAPEM: "ca", CertificatePEM: "cert",
	}, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("credential directory was not reported as new")
	}
	info, err := os.Stat(paths.Key)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode=%o", info.Mode().Perm())
	}
	if info, err := os.Stat(filepath.Dir(paths.Key)); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("credentials directory mode=%v err=%v", info.Mode().Perm(), err)
	}
	if got, want := filepath.Dir(paths.Key), filepath.Join(statePath, "credentials", "enr-a"); got != want {
		t.Fatalf("credential directory=%q want %q", got, want)
	}
}

func TestWriteEnrollmentCredentialsRejectsConflictingExistingDirectory(t *testing.T) {
	statePath := t.TempDir()
	certificate := Certificate{
		EnrollmentID:   "enr-existing",
		CAPEM:          "ca-data",
		CertificatePEM: "certificate-data",
	}
	paths, _, err := WriteCredentials(statePath, certificate, []byte("key-data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Certificate, []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := WriteCredentials(statePath, certificate, []byte("key-data")); err == nil {
		t.Fatal("conflicting credential directory was accepted")
	}
}

func TestRollbackEnrollmentCredentialsOnlyRemovesNewDirectory(t *testing.T) {
	root := t.TempDir()
	newDir := filepath.Join(root, "enr-new")
	existingDir := filepath.Join(root, "enr-existing")
	for _, dir := range []string{newDir, existingDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	rollbackEnrollmentCredentials(CredentialPaths{Key: filepath.Join(newDir, "agent-key.pem")}, true)
	rollbackEnrollmentCredentials(CredentialPaths{Key: filepath.Join(existingDir, "agent-key.pem")}, false)

	if _, err := os.Stat(newDir); !os.IsNotExist(err) {
		t.Fatalf("new credential directory still exists: %v", err)
	}
	if _, err := os.Stat(existingDir); err != nil {
		t.Fatalf("existing credential directory was removed: %v", err)
	}
}

func TestEnrollmentEndpointRejectsRelativeURL(t *testing.T) {
	if _, err := enrollmentEndpoint("manager.local"); err == nil {
		t.Fatal("relative manager URL accepted")
	}
}
