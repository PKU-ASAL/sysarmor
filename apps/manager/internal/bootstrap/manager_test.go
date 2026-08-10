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
