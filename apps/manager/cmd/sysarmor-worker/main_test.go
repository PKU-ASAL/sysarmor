package main

import (
	"os"
	"strings"
	"testing"
)

func TestWorkerCommandUsesBootstrapForComposition(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"internal/adapters/inbound/kafka",
		"internal/adapters/outbound/kafka",
		"internal/adapters/outbound/opensearch",
		"internal/adapters/outbound/postgres",
		"packages/contracts/proto",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("worker command imports composition detail %q", forbidden)
		}
	}
}

func TestWorkerCommandDependsOnBootstrapOnly(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{
		"github.com/lib/pq",
		"/internal/adapters/",
		"/packages/contracts/",
		"google.golang.org/grpc",
		"segmentio/kafka-go",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("worker command imports technical dependency %q", forbidden)
		}
	}
}

func TestSplitCSVTrimsAndDropsEmptyValues(t *testing.T) {
	got := splitCSV(" broker-a, ,broker-b ")
	if len(got) != 2 || got[0] != "broker-a" || got[1] != "broker-b" {
		t.Fatalf("splitCSV() = %#v", got)
	}
}
