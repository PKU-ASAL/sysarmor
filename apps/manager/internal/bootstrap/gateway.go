package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	grpcadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc"
	controlgrpc "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/control"
	datagrpc "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/dataplane"
	kafkaadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/kafka"
	controlpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/control"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	responsepostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/response"
	redisadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/redis"
	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway/handlers"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"google.golang.org/grpc"
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

type ControlPlaneConfig struct {
	DB         *sql.DB
	AgentToken string
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
		var errs []error
		for index := len(closers) - 1; index >= 0; index-- {
			if err := closers[index](); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}, nil
}

func NewGatewayControlPlane(cfg ControlPlaneConfig) (*controlgrpc.Server, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("gateway control database is required")
	}
	sessions := controlpostgres.NewSessionRepository(cfg.DB)
	stateWriter := controlpostgres.NewStateWriter(cfg.DB)
	state := gatewayControlStateWriter{state: stateWriter,
		results:   controlapp.NewResultService(controlpostgres.NewUnitOfWork(cfg.DB), systemClock{}, uuidGenerator{}),
		responses: responseapp.NewService(responsepostgres.NewUnitOfWork(cfg.DB), systemClock{}, uuidGenerator{})}
	delivery := controlapp.NewDeliveryService(controlpostgres.NewUnitOfWork(cfg.DB), systemClock{}, uuidGenerator{})
	pending := gatewayapp.NewPendingControlService(sessions, delivery)
	dispatcher := gatewayapp.NewDispatcher(map[string]ports.ControlHandler{
		"hello":                    handlers.NewHelloHandler(gatewayapp.NewOpenSessionService(sessions, delivery)),
		"health_report":            handlers.NewHealthHandler(state, pending),
		"capability_report":        handlers.NewStateHandler("capability_report", state),
		"response_ack":             handlers.NewStateHandler("response_ack", state),
		"ack":                      handlers.NewStateHandler("ack", state),
		"evidence_pullback_result": handlers.NewStateHandler("evidence_pullback_result", state),
	})
	certificates := identitypostgres.NewCertificateAuthorizer(cfg.DB)
	revocations := gatewayapp.NewRevokeEnrollmentService(controlpostgres.NewRevocationRepository(cfg.DB))
	return controlgrpc.NewServer(dispatcher, certificates, cfg.AgentToken, revocations), nil
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
