package bootstrap

import (
	"context"
	"strings"
	"testing"
)

func TestNewWorkerRejectsMissingDependencies(t *testing.T) {
	tests := []struct {
		name   string
		config WorkerConfig
		want   string
	}{
		{name: "postgres dsn", config: WorkerConfig{}, want: "postgres dsn"},
		{name: "kafka brokers", config: validWorkerConfig(""), want: "kafka brokers"},
		{name: "kafka topic", config: func() WorkerConfig { value := validWorkerConfig("broker:9092"); value.KafkaTopic = ""; return value }(), want: "kafka topic"},
		{name: "kafka group", config: func() WorkerConfig { value := validWorkerConfig("broker:9092"); value.KafkaGroupID = ""; return value }(), want: "kafka group"},
		{name: "opensearch", config: func() WorkerConfig { value := validWorkerConfig("broker:9092"); value.OpenSearchURL = ""; return value }(), want: "opensearch url"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewWorker(context.Background(), test.config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewWorker() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestNewWorkerRejectsNonPostgresDriver(t *testing.T) {
	config := validWorkerConfig("broker:9092")
	config.PostgresDriver = "sqlite"
	_, _, err := NewWorker(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "postgres driver must be postgres") {
		t.Fatalf("NewWorker() error=%v, want postgres-only validation", err)
	}
}

func validWorkerConfig(broker string) WorkerConfig {
	return WorkerConfig{
		PostgresDriver: "postgres", PostgresDSN: "postgres://invalid",
		KafkaBrokers: []string{broker}, KafkaTopic: "raw", KafkaGroupID: "worker",
		OpenSearchURL: "http://opensearch:9200",
	}
}
