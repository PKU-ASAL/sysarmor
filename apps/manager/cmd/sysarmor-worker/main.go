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
	config, brokers := workerFlags()
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
	worker, closer, err := bootstrap.NewWorker(openCtx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap worker: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if closeErr := closer.Close(); closeErr != nil {
			log.Printf("close worker resources: %v", closeErr)
		}
	}()
	log.Printf("sysarmor-worker consuming topic=%s group=%s storage=postgres", config.KafkaTopic, config.KafkaGroupID)
	if err := worker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "run worker: %v\n", err)
		os.Exit(1)
	}
}

func workerFlags() (bootstrap.WorkerConfig, *string) {
	config := bootstrap.WorkerConfig{}
	flag.StringVar(&config.PostgresDriver, "postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "database/sql driver name")
	flag.StringVar(&config.PostgresDSN, "postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "PostgreSQL DSN")
	var brokers string
	flag.StringVar(&brokers, "kafka-brokers", envDefault("SYSARMOR_KAFKA_BROKERS", ""), "comma-separated Kafka brokers")
	flag.StringVar(&config.KafkaTopic, "kafka-topic", envDefault("SYSARMOR_KAFKA_TOPIC", "sysarmor.agent.databatch.raw"), "Kafka raw data batch topic")
	flag.StringVar(&config.KafkaGroupID, "kafka-group-id", envDefault("SYSARMOR_KAFKA_GROUP_ID", "sysarmor-worker"), "Kafka consumer group id")
	flag.StringVar(&config.OpenSearchURL, "opensearch-url", envDefault("SYSARMOR_OPENSEARCH_URL", ""), "OpenSearch URL")
	flag.StringVar(&config.OpenSearchUsername, "opensearch-username", envDefault("SYSARMOR_OPENSEARCH_USERNAME", ""), "OpenSearch username")
	flag.StringVar(&config.OpenSearchPassword, "opensearch-password", envDefault("SYSARMOR_OPENSEARCH_PASSWORD", ""), "OpenSearch password")
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
