package main

import (
	"os"
	"strings"
	"testing"
)

func TestManagerCommandUsesPostgresBootstrap(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "bootstrap.NewManager") {
		t.Fatal("manager command must use bootstrap.NewManager")
	}
	for _, legacy := range []string{"store-backend", "\"-store\"", "/internal/store", "managerServerForBackend"} {
		if strings.Contains(text, legacy) {
			t.Fatalf("manager command still contains legacy path %q", legacy)
		}
	}
}

func TestEnvDefault(t *testing.T) {
	t.Setenv("SYSARMOR_TEST_DEFAULT", " value ")
	if got := envDefault("SYSARMOR_TEST_DEFAULT", "fallback"); got != "value" {
		t.Fatalf("envDefault = %q", got)
	}
	if got := envDefault("SYSARMOR_TEST_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("envDefault fallback = %q", got)
	}
}
