package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/bootstrap"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":9444", "gateway agent data/control gRPC listen address")
	healthListen := flag.String("health-listen", ":9445", "gateway health/metrics HTTP listen address; empty disables HTTP health")
	grpcTLSCert := flag.String("tls-cert", envDefault("SYSARMOR_GRPC_TLS_CERT", ""), "gateway gRPC server TLS certificate")
	grpcTLSKey := flag.String("tls-key", envDefault("SYSARMOR_GRPC_TLS_KEY", ""), "gateway gRPC server TLS private key")
	grpcClientCA := flag.String("client-ca", envDefault("SYSARMOR_GRPC_CLIENT_CA", ""), "CA bundle used to verify agent client certificates")
	development := flag.Bool("development", false, "allow insecure gRPC on a loopback listen address")
	postgresDriver := flag.String("postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "database/sql driver name for postgres backend")
	postgresDSN := flag.String("postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "Postgres DSN for postgres backend")
	kafkaBrokers := flag.String("kafka-brokers", envDefault("SYSARMOR_KAFKA_BROKERS", ""), "comma-separated Kafka brokers for raw telemetry ingest")
	redisAddr := flag.String("redis-addr", envDefault("SYSARMOR_REDIS_ADDR", ""), "Redis address for agent session hot state")
	devToken := flag.String("dev-token", "", "static development agent token; empty disables token checks")
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		return
	}
	prepared, err := prepareGateway(gatewaySecurityConfig{
		listen:   *listen,
		tlsCert:  *grpcTLSCert,
		tlsKey:   *grpcTLSKey,
		clientCA: *grpcClientCA,
	}, *development)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare gateway: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	db, _, err := bootstrap.OpenPostgres(openCtx, *postgresDriver, *postgresDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open postgres: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if *healthListen != "" {
		startHealthServer(ctx, *healthListen, prepared.MTLSEnabled())
	}

	dataServer, closeData, err := bootstrap.NewGatewayDataPlane(bootstrap.DataPlaneConfig{
		DB: db, KafkaBrokers: splitCSV(*kafkaBrokers), RedisAddress: *redisAddr, AgentToken: *devToken,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure gateway data plane: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := closeData(); err != nil {
			log.Printf("close gateway data plane: %v", err)
		}
	}()
	controlServer, err := bootstrap.NewGatewayControlPlane(bootstrap.ControlPlaneConfig{DB: db, AgentToken: *devToken})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure gateway control plane: %v\n", err)
		os.Exit(1)
	}
	grpcServer := grpc.NewServer(prepared.ServerOptions()...)
	dataplanev1.RegisterAgentDataPlaneServiceServer(grpcServer, dataServer)
	controlplanev1.RegisterAgentControlPlaneServiceServer(grpcServer, controlServer)

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway grpc listen: %v\n", err)
		os.Exit(1)
	}
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("sysarmor-gateway listening on %s mtls=%t", *listen, prepared.MTLSEnabled())
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Fprintf(os.Stderr, "gateway grpc serve: %v\n", err)
		os.Exit(1)
	}
}

type gatewaySecurityConfig struct {
	listen   string
	tlsCert  string
	tlsKey   string
	clientCA string
}

func prepareGateway(cfg gatewaySecurityConfig, development bool) (bootstrap.Gateway, error) {
	bootstrapConfig := bootstrap.GatewayConfig{
		Listen:   cfg.listen,
		TLSCert:  cfg.tlsCert,
		TLSKey:   cfg.tlsKey,
		ClientCA: cfg.clientCA,
	}
	if development {
		return bootstrap.NewDevelopmentGateway(bootstrapConfig)
	}
	return bootstrap.NewProductionGateway(bootstrapConfig)
}

func startHealthServer(ctx context.Context, listen string, mtlsEnabled bool) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "service": "sysarmor-gateway", "mtls": mtlsEnabled})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"service": "sysarmor-gateway", "ok": true})
	})
	server := &http.Server{Addr: listen, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		log.Printf("sysarmor-gateway health listening on %s", listen)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("gateway health serve: %v", err)
		}
	}()
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
