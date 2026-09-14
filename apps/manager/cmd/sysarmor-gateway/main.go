package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/bootstrap"
)

var version = "dev"

func main() {
	config, brokers := gatewayFlags()
	flag.Parse()
	config.KafkaBrokers = splitCSV(*brokers)
	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	openCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	runtime, closer, err := bootstrap.NewGateway(openCtx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap gateway: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if closeErr := closer.Close(); closeErr != nil {
			log.Printf("close gateway resources: %v", closeErr)
		}
	}()
	if err := runtime.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "run gateway: %v\n", err)
		os.Exit(1)
	}
}

func gatewayFlags() (bootstrap.GatewayRuntimeConfig, *string) {
	config := bootstrap.GatewayRuntimeConfig{}
	flag.StringVar(&config.Listen, "listen", ":9444", "gateway agent data/control gRPC listen address")
	flag.StringVar(&config.HealthListen, "health-listen", ":9445", "gateway health/metrics HTTP listen address; empty disables HTTP health")
	flag.StringVar(&config.TLSCert, "tls-cert", envDefault("SYSARMOR_GRPC_TLS_CERT", ""), "gateway gRPC server TLS certificate")
	flag.StringVar(&config.TLSKey, "tls-key", envDefault("SYSARMOR_GRPC_TLS_KEY", ""), "gateway gRPC server TLS private key")
	flag.StringVar(&config.ClientCA, "client-ca", envDefault("SYSARMOR_GRPC_CLIENT_CA", ""), "CA bundle used to verify agent client certificates")
	flag.BoolVar(&config.Development, "development", false, "allow insecure gRPC on a loopback listen address")
	flag.StringVar(&config.PostgresDriver, "postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "database/sql driver name")
	flag.StringVar(&config.PostgresDSN, "postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "PostgreSQL DSN")
	var brokers string
	flag.StringVar(&brokers, "kafka-brokers", envDefault("SYSARMOR_KAFKA_BROKERS", ""), "comma-separated Kafka brokers")
	flag.StringVar(&config.RedisAddress, "redis-addr", envDefault("SYSARMOR_REDIS_ADDR", ""), "Redis address for agent session hot state")
	flag.StringVar(&config.AgentToken, "dev-token", "", "static development agent token; empty disables token checks")
	return config, &brokers
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
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
