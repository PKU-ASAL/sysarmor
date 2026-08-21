package bootstrap

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	kafkain "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/kafka"
	kafkaout "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/kafka"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	opensearchworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch/worker"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	workerpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/worker"
	workerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/worker"
)

type WorkerConfig struct {
	PostgresDriver     string
	PostgresDSN        string
	KafkaBrokers       []string
	KafkaTopic         string
	KafkaGroupID       string
	OpenSearchURL      string
	OpenSearchUsername string
	OpenSearchPassword string
}

func NewWorker(ctx context.Context, config WorkerConfig) (*workerapp.Worker, io.Closer, error) {
	if err := config.validate(); err != nil {
		return nil, nil, err
	}
	db, _, err := OpenPostgres(ctx, config.PostgresDriver, config.PostgresDSN)
	if err != nil {
		return nil, nil, err
	}
	resources := &workerResources{db: db}
	consumer, err := openWorkerConsumer(ctx, config)
	if err != nil {
		_ = resources.Close()
		return nil, nil, err
	}
	resources.consumer = consumer
	if err := kafkain.EnsureTopic(ctx, config.KafkaBrokers, config.KafkaTopic+".dlq"); err != nil {
		_ = resources.Close()
		return nil, nil, fmt.Errorf("ensure kafka dead letter topic: %w", err)
	}
	dlq, err := kafkaout.NewRawProducer(config.KafkaBrokers)
	if err != nil {
		_ = resources.Close()
		return nil, nil, fmt.Errorf("open kafka dead letter producer: %w", err)
	}
	resources.dlq = dlq
	indexer, err := platformopensearch.NewHTTPIndexerWithAuth(config.OpenSearchURL, config.OpenSearchUsername, config.OpenSearchPassword)
	if err != nil {
		_ = resources.Close()
		return nil, nil, fmt.Errorf("open opensearch indexer: %w", err)
	}
	service := newWorkerProcessBatch(db, indexer)
	return workerapp.New(consumer, service, dlq, workerpostgres.NewTelemetryBatches(db)), resources, nil
}

func (config WorkerConfig) validate() error {
	checks := []struct{ value, message string }{
		{config.PostgresDSN, "postgres dsn is required"},
		{config.PostgresDriver, "postgres driver is required"},
		{config.KafkaTopic, "kafka topic is required"},
		{config.KafkaGroupID, "kafka group id is required"},
		{config.OpenSearchURL, "opensearch url is required"},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.value) == "" {
			return errors.New(check.message)
		}
	}
	if strings.TrimSpace(config.PostgresDriver) != "postgres" {
		return errors.New("postgres driver must be postgres")
	}
	if len(cleanWorkerBrokers(config.KafkaBrokers)) == 0 {
		return errors.New("kafka brokers are required")
	}
	return nil
}

func openWorkerConsumer(ctx context.Context, config WorkerConfig) (*kafkain.RawConsumer, error) {
	if err := kafkain.WaitForTopic(ctx, config.KafkaBrokers, config.KafkaTopic); err != nil {
		return nil, fmt.Errorf("wait for kafka topic: %w", err)
	}
	consumer, err := kafkain.NewRawConsumer(config.KafkaBrokers, config.KafkaTopic, config.KafkaGroupID)
	if err != nil {
		return nil, fmt.Errorf("open kafka consumer: %w", err)
	}
	return consumer, nil
}

func newWorkerProcessBatch(db *sql.DB, indexer *platformopensearch.HTTPIndexer) *workerapp.ProcessBatch {
	identityRepositories := identitypostgres.NewRepositories(db)
	policyUnitOfWork := policypostgres.NewUnitOfWork(db)
	return workerapp.NewProcessBatch(
		kafkain.NewBatchDecoder(),
		opensearchworker.NewBatchProjector(indexer),
		opensearchworker.NewOpenSearchHistory(indexer),
		identityRepositories.Snapshots(),
		workerpostgres.NewTelemetryBatches(db),
		workerpostgres.NewDetectionPolicies(policyUnitOfWork),
	)
}

type workerResources struct {
	db       *sql.DB
	consumer io.Closer
	dlq      io.Closer
}

func (resources *workerResources) Close() error {
	if resources == nil {
		return nil
	}
	var errs []error
	if resources.dlq != nil {
		errs = append(errs, resources.dlq.Close())
	}
	if resources.consumer != nil {
		errs = append(errs, resources.consumer.Close())
	}
	if resources.db != nil {
		errs = append(errs, resources.db.Close())
	}
	return errors.Join(errs...)
}

func cleanWorkerBrokers(values []string) []string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			clean = append(clean, value)
		}
	}
	return clean
}
