package bootstrap

import (
	grpcadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc"
	"google.golang.org/grpc"
)

type GatewayConfig struct {
	Listen   string
	TLSCert  string
	TLSKey   string
	ClientCA string
}

type Gateway struct {
	security grpcadapter.Security
}

func NewProductionGateway(cfg GatewayConfig) (Gateway, error) {
	security, err := grpcadapter.NewProductionSecurity(toSecurityConfig(cfg))
	if err != nil {
		return Gateway{}, err
	}
	return Gateway{security: security}, nil
}

func NewDevelopmentGateway(cfg GatewayConfig) (Gateway, error) {
	security, err := grpcadapter.NewDevelopmentSecurity(toSecurityConfig(cfg))
	if err != nil {
		return Gateway{}, err
	}
	return Gateway{security: security}, nil
}

func (g Gateway) ServerOptions() []grpc.ServerOption {
	return g.security.ServerOptions()
}

func (g Gateway) MTLSEnabled() bool {
	return g.security.MTLSEnabled()
}

func toSecurityConfig(cfg GatewayConfig) grpcadapter.SecurityConfig {
	return grpcadapter.SecurityConfig{
		Listen:   cfg.Listen,
		TLSCert:  cfg.TLSCert,
		TLSKey:   cfg.TLSKey,
		ClientCA: cfg.ClientCA,
	}
}
