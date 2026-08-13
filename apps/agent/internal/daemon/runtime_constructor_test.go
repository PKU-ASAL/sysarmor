package daemon

import (
	"strings"
	"testing"
)

func TestNewRuntimeRejectsMissingCompositionDependencies(t *testing.T) {
	_, err := NewRuntime(Dependencies{})
	if err == nil || !strings.Contains(err.Error(), "sensor") {
		t.Fatalf("NewRuntime() error = %v, want missing sensor error", err)
	}
}
