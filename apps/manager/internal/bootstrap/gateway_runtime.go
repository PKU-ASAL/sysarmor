package bootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc"
)

type GatewayRuntimeConfig struct {
	Listen         string
	HealthListen   string
	TLSCert        string
	TLSKey         string
	ClientCA       string
	Development    bool
	PostgresDriver string
	PostgresDSN    string
	KafkaBrokers   []string
	RedisAddress   string
	AgentToken     string
}

type GatewayRuntime struct {
	grpcServer   *grpc.Server
	grpcListener net.Listener
	healthServer *http.Server
	healthListen net.Listener
	listen       string
	mtls         bool
	stopOnce     sync.Once
}

func NewGateway(ctx context.Context, config GatewayRuntimeConfig) (*GatewayRuntime, io.Closer, error) {
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	security, err := newGatewaySecurity(config)
	if err != nil {
		return nil, nil, err
	}
	db, err := OpenPostgresConnection(config.PostgresDriver, config.PostgresDSN)
	if err != nil {
		return nil, nil, err
	}
	resources := &gatewayResources{db: db}
	runtime, err := buildGatewayRuntime(config, security, db, resources)
	if err != nil {
		_ = resources.Close()
		return nil, nil, err
	}
	return runtime, resources, nil
}

func (config GatewayRuntimeConfig) validate() error {
	checks := []struct{ value, message string }{
		{config.Listen, "gateway listen address is required"},
		{config.PostgresDSN, "postgres dsn is required"},
		{config.PostgresDriver, "postgres driver is required"},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.value) == "" {
			return errors.New(check.message)
		}
	}
	if strings.TrimSpace(config.PostgresDriver) != "postgres" {
		return errors.New("postgres driver must be postgres")
	}
	if len(cleanKafkaBrokers(config.KafkaBrokers)) == 0 {
		return errors.New("kafka brokers are required")
	}
	return nil
}

func cleanKafkaBrokers(values []string) []string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}

func newGatewaySecurity(config GatewayRuntimeConfig) (Gateway, error) {
	securityConfig := GatewayConfig{Listen: config.Listen, TLSCert: config.TLSCert, TLSKey: config.TLSKey, ClientCA: config.ClientCA}
	if config.Development {
		return NewDevelopmentGateway(securityConfig)
	}
	return NewProductionGateway(securityConfig)
}

func buildGatewayRuntime(config GatewayRuntimeConfig, security Gateway, db *sql.DB, resources *gatewayResources) (*GatewayRuntime, error) {
	data, metrics, closeData, err := NewGatewayDataPlane(DataPlaneConfig{
		DB: db, KafkaBrokers: config.KafkaBrokers, RedisAddress: config.RedisAddress, AgentToken: config.AgentToken,
	})
	if err != nil {
		return nil, err
	}
	resources.dataPlane = closerFunc(closeData)
	control, err := NewGatewayControlPlane(ControlPlaneConfig{DB: db, AgentToken: config.AgentToken})
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(security.ServerOptions()...)
	dataplanev1.RegisterAgentDataPlaneServiceServer(server, data)
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, control)
	return openGatewayListeners(config, security.MTLSEnabled(), server, metrics, resources)
}

func openGatewayListeners(config GatewayRuntimeConfig, mtls bool, server *grpc.Server, metrics *gatewayapp.BatchMetrics, resources *gatewayResources) (*GatewayRuntime, error) {
	grpcListener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen for gateway gRPC: %w", err)
	}
	resources.grpcListener = grpcListener
	runtime := &GatewayRuntime{grpcServer: server, grpcListener: grpcListener, listen: config.Listen, mtls: mtls}
	if strings.TrimSpace(config.HealthListen) == "" {
		return runtime, nil
	}
	healthListener, err := net.Listen("tcp", config.HealthListen)
	if err != nil {
		return nil, fmt.Errorf("listen for gateway health: %w", err)
	}
	resources.healthListener = healthListener
	runtime.healthListen = healthListener
	runtime.healthServer = newGatewayHealthServer(config.HealthListen, mtls, metrics)
	return runtime, nil
}

func (runtime *GatewayRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.grpcServer == nil || runtime.grpcListener == nil {
		return errors.New("gateway runtime is incomplete")
	}
	grpcErrors := make(chan error, 1)
	healthErrors := make(chan error, 1)
	if runtime.healthServer != nil {
		go runtime.serveHealth(healthErrors)
	}
	go func() {
		if err := runtime.grpcServer.Serve(runtime.grpcListener); err != nil && !errors.Is(err, net.ErrClosed) {
			grpcErrors <- fmt.Errorf("serve gateway gRPC: %w", err)
			return
		}
		grpcErrors <- nil
	}()
	go func() {
		<-ctx.Done()
		runtime.stop()
	}()
	log.Printf("sysarmor-gateway listening on %s mtls=%t", runtime.listen, runtime.mtls)
	select {
	case err := <-grpcErrors:
		runtime.stop()
		return err
	case err := <-healthErrors:
		runtime.stop()
		return err
	case <-ctx.Done():
		runtime.stop()
		return nil
	}
}

func (runtime *GatewayRuntime) serveHealth(result chan<- error) {
	log.Printf("sysarmor-gateway health listening on %s", runtime.healthServer.Addr)
	if err := runtime.healthServer.Serve(runtime.healthListen); err != nil && err != http.ErrServerClosed {
		result <- fmt.Errorf("serve gateway health: %w", err)
	}
}

func (runtime *GatewayRuntime) stop() {
	runtime.stopOnce.Do(func() {
		if runtime.healthServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = runtime.healthServer.Shutdown(shutdownCtx)
		}
		gracefulDone := make(chan struct{})
		go func() {
			runtime.grpcServer.GracefulStop()
			close(gracefulDone)
		}()
		select {
		case <-gracefulDone:
		case <-time.After(3 * time.Second):
			runtime.grpcServer.Stop()
		}
	})
}

func newGatewayHealthServer(address string, mtls bool, metrics *gatewayapp.BatchMetrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeGatewayJSON(writer, map[string]any{"ok": true, "service": "sysarmor-gateway", "mtls": mtls})
	})
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, _ *http.Request) {
		writeGatewayJSON(writer, metrics.Snapshot())
	})
	return &http.Server{Addr: address, Handler: mux}
}

func writeGatewayJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

type gatewayResources struct {
	db             io.Closer
	dataPlane      io.Closer
	grpcListener   io.Closer
	healthListener io.Closer
}

func (resources *gatewayResources) Close() error {
	if resources == nil {
		return nil
	}
	return errors.Join(closeListener(resources.healthListener), closeListener(resources.grpcListener), closeIfPresent(resources.dataPlane), closeIfPresent(resources.db))
}

func closeListener(closer io.Closer) error {
	err := closeIfPresent(closer)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func closeIfPresent(closer io.Closer) error {
	if closer == nil {
		return nil
	}
	return closer.Close()
}

type closerFunc func() error

func (close closerFunc) Close() error { return close() }
