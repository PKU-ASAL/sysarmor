package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
)

const completionProtocol = "completion_v1"

type Issuer struct {
	ca          *x509.Certificate
	key         *rsa.PrivateKey
	caPEM       []byte
	trustDomain string
}

func NewIssuer(certificatePEM, keyPEM []byte, trustDomain string) (*Issuer, error) {
	certificate, err := parseCertificate(certificatePEM)
	if err != nil {
		return nil, err
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	trustDomain = strings.TrimSpace(trustDomain)
	if trustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}
	return &Issuer{ca: certificate, key: key, caPEM: append([]byte(nil), certificatePEM...), trustDomain: trustDomain}, nil
}

func (issuer *Issuer) Issue(_ context.Context, enrollment domainenrollment.Enrollment, csrPEM []byte) (domainenrollment.Issuance, error) {
	csr, err := parseRequest(csrPEM)
	if err != nil {
		return domainenrollment.Issuance{}, err
	}
	identity, err := issuer.identityURI(enrollment)
	if err != nil {
		return domainenrollment.Issuance{}, err
	}
	now := time.Now().UTC()
	template, err := certificateTemplate(enrollment, identity, now)
	if err != nil {
		return domainenrollment.Issuance{}, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.ca, csr.PublicKey, issuer.key)
	if err != nil {
		return domainenrollment.Issuance{}, fmt.Errorf("sign agent certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return domainenrollment.Issuance{}, fmt.Errorf("parse signed certificate: %w", err)
	}
	keyHash := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return domainenrollment.Issuance{KeySHA256: hex.EncodeToString(keyHash[:]), CAPEM: string(issuer.caPEM),
		Certificate: mapCertificate(certificate, der)}, nil
}

func (issuer *Issuer) identityURI(enrollment domainenrollment.Enrollment) (*url.URL, error) {
	if enrollment.TenantID == "" || strings.TrimSpace(enrollment.AgentID) == "" {
		return nil, fmt.Errorf("enrollment identity is incomplete")
	}
	return url.Parse(fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", issuer.trustDomain, enrollment.TenantID, enrollment.AgentID))
}

func certificateTemplate(enrollment domainenrollment.Enrollment, identity *url.URL, now time.Time) (*x509.Certificate, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("create certificate serial: %w", err)
	}
	return &x509.Certificate{SerialNumber: serial,
		Subject:   pkix.Name{CommonName: fmt.Sprintf("tenant_id:%s,agent_id:%s", enrollment.TenantID, enrollment.AgentID)},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
		URIs: []*url.URL{identity}}, nil
}

func mapCertificate(certificate *x509.Certificate, der []byte) domainenrollment.Certificate {
	return domainenrollment.Certificate{SerialNumber: certificate.SerialNumber.String(),
		UnenrollmentProtocol: completionProtocol, Subject: certificate.Subject.String(), NotBefore: certificate.NotBefore,
		NotAfter: certificate.NotAfter, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func parseCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate authority must contain a CERTIFICATE")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate authority: %w", err)
	}
	return certificate, nil
}

func parsePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("certificate authority key is invalid")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate authority key: %w", err)
	}
	return key, nil
}

func parseRequest(raw []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("csr must be PEM encoded CERTIFICATE REQUEST")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify csr signature: %w", err)
	}
	return request, nil
}
