package bootstrap

import (
	"context"
	"strings"
	"testing"
)

func TestNewManagerRejectsMissingPostgresDSN(t *testing.T) {
	_, _, err := NewManager(context.Background(), ManagerConfig{})
	if err == nil || !strings.Contains(err.Error(), "postgres dsn is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewManagerRejectsNonPostgresDriver(t *testing.T) {
	_, _, err := NewManager(context.Background(), ManagerConfig{PostgresDriver: "sqlite", PostgresDSN: "file:test.db"})
	if err == nil || !strings.Contains(err.Error(), "postgres driver must be postgres") {
		t.Fatalf("err = %v", err)
	}
}
