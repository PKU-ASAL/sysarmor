package grpcadapter

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type SecurityConfig struct {
	Listen   string
	TLSCert  string
	TLSKey   string
	ClientCA string
}

type Security struct {
	serverOptions []grpc.ServerOption
	mtlsEnabled   bool
}

func NewProductionSecurity(cfg SecurityConfig) (Security, error) {
	option, err := mtlsServerOption(cfg.TLSCert, cfg.TLSKey, cfg.ClientCA)
	if err != nil {
		return Security{}, fmt.Errorf("production gateway mTLS: %w", err)
	}
	return Security{serverOptions: []grpc.ServerOption{option}, mtlsEnabled: true}, nil
}

func mtlsServerOption(certFile, keyFile, clientCAFile string) (grpc.ServerOption, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("mTLS cert and key are required")
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("mTLS requires a client CA")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	clientCA, err := loadCertPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
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

func NewDevelopmentSecurity(cfg SecurityConfig) (Security, error) {
	if cfg.TLSCert != "" || cfg.TLSKey != "" || cfg.ClientCA != "" {
		return Security{}, fmt.Errorf("development gateway does not accept TLS configuration")
	}
	if err := requireLoopback(cfg.Listen); err != nil {
		return Security{}, err
	}
	return Security{}, nil
}

func (s Security) ServerOptions() []grpc.ServerOption {
	return append([]grpc.ServerOption(nil), s.serverOptions...)
}

func (s Security) MTLSEnabled() bool {
	return s.mtlsEnabled
}

func requireLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("development gateway listen address %q: %w", address, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("insecure development gateway must listen on loopback, got %q", address)
	}
	return nil
}
