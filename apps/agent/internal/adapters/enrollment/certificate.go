package enrollment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxEnrollmentResponseBytes = 1 << 20

type Certificate struct {
	SchemaVersion     string `json:"schema_version"`
	EnrollmentID      string `json:"enrollment_id"`
	TenantID          string `json:"tenant_id"`
	AgentID           string `json:"agent_id"`
	SerialNumber      string `json:"serial_number"`
	GatewayAddress    string `json:"gateway_address"`
	GatewayServerName string `json:"gateway_server_name"`
	CertificatePEM    string `json:"certificate_pem"`
	CAPEM             string `json:"ca_pem"`
}

type CredentialPaths struct {
	CA, Certificate, Key string
}

func RequestCertificate(ctx context.Context, managerURL, token, statePath string) (Certificate, []byte, string, error) {
	key, keyPEM, pendingPath, err := loadOrCreatePendingEnrollmentKey(statePath, token)
	if err != nil {
		return Certificate{}, nil, "", err
	}
	csr, err := createEnrollmentCSR(key)
	if err != nil {
		return Certificate{}, nil, "", err
	}
	endpoint, err := enrollmentEndpoint(managerURL)
	if err != nil {
		return Certificate{}, nil, "", err
	}
	body, _ := json.Marshal(map[string]string{"token": token, "csr": string(csr)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Certificate{}, nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return Certificate{}, nil, "", fmt.Errorf("request enrollment certificate: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollmentResponseBytes+1))
	if err != nil || len(raw) > maxEnrollmentResponseBytes {
		return Certificate{}, nil, "", fmt.Errorf("read enrollment response")
	}
	if resp.StatusCode != http.StatusOK {
		return Certificate{}, nil, "", fmt.Errorf("manager rejected enrollment: HTTP %d", resp.StatusCode)
	}
	var certificate Certificate
	if err := json.Unmarshal(raw, &certificate); err != nil {
		return Certificate{}, nil, "", fmt.Errorf("decode enrollment response: %w", err)
	}
	if certificate.SchemaVersion != "sysarmor.enrollment/v2" || certificate.EnrollmentID == "" ||
		certificate.TenantID == "" || certificate.AgentID == "" || certificate.SerialNumber == "" || certificate.GatewayAddress == "" {
		return Certificate{}, nil, "", fmt.Errorf("enrollment response is incomplete")
	}
	if err := validateEnrollmentCertificate(certificate, key); err != nil {
		return Certificate{}, nil, "", err
	}
	return certificate, keyPEM, pendingPath, nil
}

func createEnrollmentCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("enrollment private key is required")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func loadOrCreatePendingEnrollmentKey(statePath, token string) (*ecdsa.PrivateKey, []byte, string, error) {
	if strings.TrimSpace(statePath) == "" || strings.TrimSpace(token) == "" {
		return nil, nil, "", fmt.Errorf("state path and enrollment token are required")
	}
	dir := filepath.Join(statePath, "credentials", "pending")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".pem")
	if data, err := os.ReadFile(path); err == nil {
		key, parseErr := parseEnrollmentKey(data)
		return key, data, path, parseErr
	} else if !os.IsNotExist(err) {
		return nil, nil, "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeAtomicFile(path, keyPEM, 0o600); err != nil {
		return nil, nil, "", err
	}
	return key, keyPEM, path, nil
}

func parseEnrollmentKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pending enrollment key is invalid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pending enrollment key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pending enrollment key is not ECDSA")
	}
	return key, nil
}

func enrollmentEndpoint(base string) (string, error) {
	base, err := normalizeManagerURL(base)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/v1/enrollment-certificate"
	return u.String(), nil
}

func normalizeManagerURL(base string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("manager_url must be an absolute HTTP(S) URL")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func validateEnrollmentCertificate(response Certificate, key *ecdsa.PrivateKey) error {
	caBlock, _ := pem.Decode([]byte(response.CAPEM))
	certBlock, _ := pem.Decode([]byte(response.CertificatePEM))
	if caBlock == nil || certBlock == nil {
		return fmt.Errorf("enrollment response contains invalid PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrollment CA: %w", err)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrollment certificate: %w", err)
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return fmt.Errorf("enrollment certificate does not match private key")
	}
	wantCN := fmt.Sprintf("tenant_id:%s,agent_id:%s", response.TenantID, response.AgentID)
	if cert.Subject.CommonName != wantCN {
		return fmt.Errorf("enrollment certificate identity mismatch")
	}
	if cert.SerialNumber.String() != response.SerialNumber {
		return fmt.Errorf("enrollment certificate serial mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return fmt.Errorf("verify enrollment certificate: %w", err)
	}
	return nil
}

func WriteCredentials(statePath string, certificate Certificate, keyPEM []byte) (CredentialPaths, bool, error) {
	if certificate.EnrollmentID == "" || filepath.Base(certificate.EnrollmentID) != certificate.EnrollmentID {
		return CredentialPaths{}, false, fmt.Errorf("invalid enrollment id")
	}
	root := filepath.Join(statePath, "credentials")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return CredentialPaths{}, false, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return CredentialPaths{}, false, err
	}
	dir := filepath.Join(root, certificate.EnrollmentID)
	paths := CredentialPaths{CA: filepath.Join(dir, "ca.pem"), Certificate: filepath.Join(dir, "agent.pem"), Key: filepath.Join(dir, "agent-key.pem")}
	if _, err := os.Stat(dir); err == nil {
		if err := verifyCredentialDirectory(dir, paths, certificate, keyPEM); err != nil {
			return CredentialPaths{}, false, err
		}
		return paths, false, nil
	} else if !os.IsNotExist(err) {
		return CredentialPaths{}, false, err
	}
	tmp, err := os.MkdirTemp(root, ".credentials-")
	if err != nil {
		return CredentialPaths{}, false, err
	}
	defer os.RemoveAll(tmp)
	if err := os.Chmod(tmp, 0o700); err != nil {
		return CredentialPaths{}, false, err
	}
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"ca.pem", []byte(certificate.CAPEM), 0o644}, {"agent.pem", []byte(certificate.CertificatePEM), 0o644}, {"agent-key.pem", keyPEM, 0o600}} {
		if err := writeAtomicFile(filepath.Join(tmp, file.name), file.data, file.mode); err != nil {
			return CredentialPaths{}, false, err
		}
	}
	if err := os.Rename(tmp, dir); err != nil {
		return CredentialPaths{}, false, err
	}
	return paths, true, nil
}

func verifyCredentialDirectory(dir string, paths CredentialPaths, certificate Certificate, keyPEM []byte) error {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("existing credential directory is invalid")
	}
	for _, expected := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.CA, []byte(certificate.CAPEM), 0o644},
		{paths.Certificate, []byte(certificate.CertificatePEM), 0o644},
		{paths.Key, keyPEM, 0o600},
	} {
		data, err := os.ReadFile(expected.path)
		if err != nil || !bytes.Equal(data, expected.data) {
			return fmt.Errorf("existing credential file %s does not match enrollment", filepath.Base(expected.path))
		}
		info, err := os.Stat(expected.path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != expected.mode {
			return fmt.Errorf("existing credential file %s has invalid permissions", filepath.Base(expected.path))
		}
	}
	return nil
}

func rollbackEnrollmentCredentials(paths CredentialPaths, created bool) error {
	if !created {
		return nil
	}
	if paths.Key == "" {
		return fmt.Errorf("credential key path is empty")
	}
	return os.RemoveAll(filepath.Dir(paths.Key))
}

func writeAtomicFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
