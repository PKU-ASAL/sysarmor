package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	_ "modernc.org/sqlite"
)

func TestNewManagerEnrollmentHTTPRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewManagerEnrollmentHTTP(EnrollmentHTTPConfig{}); err == nil {
		t.Fatal("empty enrollment HTTP config accepted")
	}
}

func TestNewManagerEnrollmentHTTPRequiresRequestContextResolver(t *testing.T) {
	_, err := NewManagerEnrollmentHTTP(EnrollmentHTTPConfig{DB: &sql.DB{}})
	if err == nil || !strings.Contains(err.Error(), "request context resolver") {
		t.Fatalf("resolver error = %v", err)
	}
}

func TestNewManagerEnrollmentHTTPWiresEnrollmentQuery(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE enrollments (tenant_id TEXT, enrollment_id TEXT, token_hash TEXT, status TEXT, created_at TIMESTAMP, data BLOB)`,
		`CREATE TABLE agent_unenrollments (tenant_id TEXT, enrollment_id TEXT, data BLOB)`,
		`CREATE TABLE artifacts (tenant_id TEXT, artifact_id TEXT, sha256 TEXT, status TEXT, storage_path TEXT, data BLOB)`,
		`CREATE TABLE artifact_channels (tenant_id TEXT, channel_name TEXT, artifact_id TEXT, data BLOB)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	certFile, keyFile := writeEnrollmentTestCA(t)
	tenantID, _ := tenant.NewID("tenant-a")
	artifactDir := t.TempDir()
	handler, err := NewManagerEnrollmentHTTP(EnrollmentHTTPConfig{
		DB: db, CACertFile: certFile, CAKeyFile: keyFile, ArtifactPublicKeyFile: certFile,
		ArtifactDir: artifactDir,
		Resolve: func(*http.Request) (managerapp.RequestContext, error) {
			return managerapp.RequestContext{Actor: tenant.Actor{
				Subject: "viewer-a", TenantID: tenantID, Roles: tenant.NewRoleSet(tenant.RoleViewer),
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.Enrollments(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/enrollments", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"enrollments\":[]}\n" {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.Install(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/agent-install.sh?ticket=missing", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("install status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/enrollment-artifact", nil)
	request.Header.Set("Authorization", "Enrollment missing")
	handler.Artifact(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("artifact status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func writeEnrollmentTestCA(t *testing.T) (string, string) {
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
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "ca.crt"), filepath.Join(directory, "ca.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
