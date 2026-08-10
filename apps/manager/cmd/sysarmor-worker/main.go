package main

import (
	"context"
	"encoding/json"
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
	kafkain "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/kafka"
	kafkaout "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/kafka"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	workerpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/worker"
	managerpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	workerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/worker"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/bootstrap"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
	"google.golang.org/protobuf/encoding/protojson"
)

var version = "dev"

func main() {
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
	if strings.TrimSpace(*opensearchURL) == "" {
		fmt.Fprintln(os.Stderr, "open opensearch indexer: opensearch url is required")
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

	consumer, err := kafkain.WaitForConsumer(ctx, func() (*kafkain.RawConsumer, error) {
		return kafkain.NewRawConsumer(splitCSV(*kafkaBrokers), *kafkaTopic, *kafkaGroupID)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open kafka consumer: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := consumer.Close(); err != nil {
			log.Printf("close kafka consumer: %v", err)
		}
	}()
	dlqProducer, err := kafkaout.NewRawProducer(splitCSV(*kafkaBrokers))
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

	log.Printf("sysarmor-worker consuming topic=%s group=%s store_backend=postgres", *kafkaTopic, *kafkaGroupID)
	identityRepositories := identitypostgres.NewRepositories(db)
	policyQueries := managerpolicy.NewQueryService(policypostgres.NewUnitOfWork(db))
	processor := ingestworker.NewRemoteProcessor(indexer, ingestworker.NewOpenSearchHistory(indexer), identityRepositories.Snapshots(), workerpostgres.NewTelemetryBatches(db), workerapp.NewDetectionPolicies(policyQueries, identityRepositories.Health()))
	err = workerapp.New(consumer, batchProcessor{processor: processor}, dlqProducer).Run(ctx)
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

type batchProcessor struct{ processor *ingestworker.Processor }

func (processor batchProcessor) Process(ctx context.Context, message ports.RawMessage) error {
	batch := &dataplanev1.DataBatch{}
	if err := protojson.Unmarshal(message.Value, batch); err != nil {
		return permanentMessage(message, "invalid_data_batch", err)
	}
	if _, err := schema.ValidateDataPlane(batch.GetSchemaVersion()); err != nil {
		return permanentMessage(message, "unsupported_schema_version", err)
	}
	if batch.GetHeader() == nil || batch.GetHeader().GetBatchId() == "" || batch.GetHeader().GetTenantId() == "" || batch.GetHeader().GetAgentId() == "" {
		return permanentMessage(message, "invalid_data_batch", errors.New("batch identity is required"))
	}
	stabilizeBatchTime(batch, time.Now().UTC())
	if _, err := processor.processor.Process(ctx, batch); err != nil {
		if platformopensearch.ErrorClassOf(err) == platformopensearch.ErrorPermanent {
			return permanentMessage(message, "permanent_projection", err)
		}
		return err
	}
	return nil
}

func stabilizeBatchTime(batch *dataplanev1.DataBatch, fallback time.Time) {
	latest := batch.GetHeader().GetCreatedAtUnixNano()
	for _, frame := range batch.GetEvents() {
		if eventTime := int64(frame.GetEvent().GetOccurredAtNs()); eventTime > latest {
			latest = eventTime
		}
		if observed, err := time.Parse(time.RFC3339Nano, frame.GetObservedAt()); err == nil && observed.UnixNano() > latest {
			latest = observed.UnixNano()
		}
	}
	for _, frame := range batch.GetSignals() {
		if observed, err := time.Parse(time.RFC3339Nano, frame.GetObservedAt()); err == nil && observed.UnixNano() > latest {
			latest = observed.UnixNano()
		}
	}
	if latest <= 0 {
		latest = fallback.UnixNano()
	}
	batch.Header.CreatedAtUnixNano = latest
}

func permanentMessage(message ports.RawMessage, class string, cause error) error {
	envelope, _ := json.Marshal(map[string]any{"source_topic": message.Topic, "source_partition": message.Partition, "source_offset": message.Offset, "source_key": message.Key, "failure_class": class, "failure_message": cause.Error(), "failure_code": class, "payload": message.Value})
	deadLetter := message
	deadLetter.Value = envelope
	return ports.PermanentError{Err: cause, Message: &deadLetter}
}
