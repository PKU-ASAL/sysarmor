package bootstrap

import (
	"context"
	"database/sql"
	grpcadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc"
	datagrpc "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/dataplane"
	kafkaadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/kafka"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	redisadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/redis"
	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"google.golang.org/grpc"
	"time"
)

type GatewayConfig struct {
	Listen   string
	TLSCert  string
	TLSKey   string
	ClientCA string
}

type DataPlaneConfig struct {
	DB                       *sql.DB
	KafkaBrokers             []string
	RedisAddress, AgentToken string
}

func NewGatewayDataPlane(cfg DataPlaneConfig) (*datagrpc.Server, func() error, error) {
	publisher, err := kafkaadapter.NewBatchPublisher(cfg.KafkaBrokers)
	if err != nil {
		return nil, nil, err
	}
	var hot gatewayHotSession
	closers := []func() error{publisher.Close}
	if cfg.RedisAddress != "" {
		writer, err := redisadapter.NewHotSessionWriter(cfg.RedisAddress, 2*time.Minute)
		if err != nil {
			_ = publisher.Close()
			return nil, nil, err
		}
		hot = writer
		closers = append(closers, writer.Close)
	}
	sessions := identitypostgres.NewGatewaySessionStore(cfg.DB)
	acceptor := gatewayapp.NewBatchAcceptor(publisher, sessions, hot)
	server := datagrpc.NewServer(acceptor, identitypostgres.NewCertificateAuthorizer(cfg.DB), cfg.AgentToken)
	return server, func() error {
		for index := len(closers) - 1; index >= 0; index-- {
			if err := closers[index](); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

type gatewayHotSession interface {
	Touch(context.Context, ports.GatewaySession) error
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
