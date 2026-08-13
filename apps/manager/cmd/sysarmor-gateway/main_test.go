package main

import (
	"os"
	"strings"
	"testing"
)

func TestGatewayCommandDependsOnBootstrapOnly(t *testing.T) {
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
		"bootstrap.OpenPostgres",
		"bootstrap.NewGatewayDataPlane",
		"bootstrap.NewGatewayControlPlane",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("gateway command owns technical dependency %q", forbidden)
		}
	}
	if !strings.Contains(text, "bootstrap.NewGateway") {
		t.Fatal("gateway command must use bootstrap.NewGateway")
	}
}

func TestSplitCSVTrimsAndDropsEmptyValues(t *testing.T) {
	got := splitCSV(" broker-a, ,broker-b ")
	if len(got) != 2 || got[0] != "broker-a" || got[1] != "broker-b" {
		t.Fatalf("splitCSV() = %#v", got)
	}
}
