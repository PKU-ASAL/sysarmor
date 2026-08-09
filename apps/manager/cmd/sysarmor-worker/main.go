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

	_ "github.com/lib/pq"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	platformkafka "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/kafka"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/platform/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/backend"
)

var version = "dev"

func main() {
	storeBackend := flag.String("store-backend", backend.KindPostgres, "store backend: postgres")
	postgresDriver := flag.String("postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "database/sql driver name for postgres backend")
	postgresDSN := flag.String("postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "Postgres DSN for postgres backend")
	kafkaBrokers := flag.String("kafka-brokers", envDefault("SYSARMOR_KAFKA_BROKERS", ""), "comma-separated Kafka brokers for raw telemetry ingest")
	kafkaTopic := flag.String("kafka-topic", envDefault("SYSARMOR_KAFKA_TOPIC", "sysarmor.agent.databatch.raw"), "Kafka raw data batch topic")
	kafkaGroupID := flag.String("kafka-group-id", envDefault("SYSARMOR_KAFKA_GROUP_ID", "sysarmor-ingest-worker"), "Kafka consumer group id")
	opensearchURL := flag.String("opensearch-url", envDefault("SYSARMOR_OPENSEARCH_URL", ""), "OpenSearch URL for searchable security data")
	opensearchUsername := flag.String("opensearch-username", envDefault("SYSARMOR_OPENSEARCH_USERNAME", ""), "OpenSearch basic auth username")
	opensearchPassword := flag.String("opensearch-password", envDefault("SYSARMOR_OPENSEARCH_PASSWORD", ""), "OpenSearch basic auth password")
	flag.Parse()

	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		return
	}
	if *storeBackend == backend.KindFile {
		fmt.Fprintln(os.Stderr, "open store: file backend has been removed from the sysarmor-worker product path; use postgres")
		os.Exit(1)
	}
	if strings.TrimSpace(*opensearchURL) == "" {
		fmt.Fprintln(os.Stderr, "open opensearch indexer: opensearch url is required")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	openCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	storeResult, err := backend.Open(openCtx, backend.Options{
		Kind:           *storeBackend,
		PostgresDriver: *postgresDriver,
		PostgresDSN:    *postgresDSN,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := storeResult.Close(); err != nil {
			log.Printf("close store backend: %v", err)
		}
	}()

	consumer, err := openKafkaConsumerWithRetry(ctx, splitCSV(*kafkaBrokers), *kafkaTopic, *kafkaGroupID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open kafka consumer: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("close kafka consumer: %v", err)
		}
	}()
	dlqProducer, err := platformkafka.NewWriterProducer(splitCSV(*kafkaBrokers))
	if err != nil {
		fmt.Fprintf(os.Stderr, "open kafka dead letter producer: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := dlqProducer.Close(); err != nil {
			log.Printf("close kafka dead letter producer: %v", err)
		}
	}()

	indexer, err := platformopensearch.NewHTTPIndexerWithAuth(*opensearchURL, *opensearchUsername, *opensearchPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open opensearch indexer: %v\n", err)
		os.Exit(1)
	}

	log.Printf("sysarmor-worker consuming topic=%s group=%s store_backend=%s", *kafkaTopic, *kafkaGroupID, *storeBackend)
	processor := ingestworker.NewProcessorWithHistory(storeResult.Store, indexer, ingestworker.NewOpenSearchHistory(indexer))
	if storeResult.DB != nil {
		processor.SetRarityReader(identitypostgres.NewRepositories(storeResult.DB).Snapshots())
	}
	err = ingestworker.NewWorkerWithDLQ(consumer, processor, dlqProducer).Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "run ingest worker: %v\n", err)
		os.Exit(1)
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

func openKafkaConsumerWithRetry(ctx context.Context, brokers []string, topic, groupID string) (*platformkafka.ReaderConsumer, error) {
	var lastErr error
	for attempt := 0; attempt < 30; attempt++ {
		consumer, err := platformkafka.NewReaderConsumer(brokers, topic, groupID)
		if err == nil {
			return consumer, nil
		}
		lastErr = err
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}
