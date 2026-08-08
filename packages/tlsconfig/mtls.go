package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
)

type ClientConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
}

type PeerIdentity struct {
	TenantID          string
	AgentID           string
	Principal         string
	CertificateSerial string
}

func ClientCredentials(cfg ClientConfig) (credentials.TransportCredentials, error) {
	if cfg.Insecure || (cfg.CAFile == "" && cfg.CertFile == "" && cfg.KeyFile == "") {
		return insecure.NewCredentials(), nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CAFile != "" {
		pool, err := loadCertPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, fmt.Errorf("both client cert and key are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return credentials.NewTLS(tlsCfg), nil
}

func MTLSServerOption(certFile, keyFile, clientCAFile string) (grpc.ServerOption, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("grpc mTLS cert and key are required")
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("grpc mTLS requires a client CA")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	pool, err := loadCertPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	tlsCfg.ClientCAs = pool
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	return grpc.Creds(credentials.NewTLS(tlsCfg)), nil
}

func PeerAgentIdentity(ctx context.Context) (PeerIdentity, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return PeerIdentity{}, false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return PeerIdentity{}, false
	}
	cert := info.State.PeerCertificates[0]
	for _, uri := range cert.URIs {
		if id, ok := identityFromURI(uri); ok {
			id.CertificateSerial = cert.SerialNumber.String()
			return id, true
		}
	}
	if id, ok := identityFromCommonName(cert.Subject.CommonName); ok {
		id.CertificateSerial = cert.SerialNumber.String()
		return id, true
	}
	return PeerIdentity{}, false
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file has no PEM certificates: %s", path)
	}
	return pool, nil
}

func identityFromURI(uri *url.URL) (PeerIdentity, bool) {
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] != "tenant" {
			continue
		}
		for j := i + 2; j+1 < len(parts); j++ {
			if parts[j] == "agent" && parts[i+1] != "" && parts[j+1] != "" {
				return PeerIdentity{TenantID: parts[i+1], AgentID: parts[j+1], Principal: uri.String()}, true
			}
		}
	}
	q := uri.Query()
	if q.Get("tenant_id") != "" && q.Get("agent_id") != "" {
		return PeerIdentity{TenantID: q.Get("tenant_id"), AgentID: q.Get("agent_id"), Principal: uri.String()}, true
	}
	return PeerIdentity{}, false
}

func identityFromCommonName(cn string) (PeerIdentity, bool) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return PeerIdentity{}, false
	}
	if tenant, agent, ok := strings.Cut(cn, "/"); ok && tenant != "" && agent != "" {
		return PeerIdentity{TenantID: tenant, AgentID: agent, Principal: "cn:" + cn}, true
	}
	var id PeerIdentity
	for _, part := range strings.Split(cn, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			key, value, ok = strings.Cut(strings.TrimSpace(part), ":")
		}
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "tenant", "tenant_id":
			id.TenantID = strings.TrimSpace(value)
		case "agent", "agent_id":
			id.AgentID = strings.TrimSpace(value)
		}
	}
	if id.TenantID != "" && id.AgentID != "" {
		id.Principal = "cn:" + cn
		return id, true
	}
	return PeerIdentity{}, false
}
