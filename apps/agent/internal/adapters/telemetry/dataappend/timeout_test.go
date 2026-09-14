package dataappend

import (
	"testing"
	"time"
)

func TestGRPCAppenderUsesConfiguredTimeout(t *testing.T) {
	up := NewGRPCAppenderWithTimeout("127.0.0.1:9443", 250*time.Millisecond)
	if up.timeout != 250*time.Millisecond {
		t.Fatalf("timeout = %s", up.timeout)
	}
}

func TestGRPCAppenderFallsBackToDefaultTimeout(t *testing.T) {
	up := NewGRPCAppenderWithTimeout("127.0.0.1:9443", 0)
	if up.timeout != 10*time.Second {
		t.Fatalf("timeout = %s", up.timeout)
	}
}

func TestGRPCAppenderStoresAgentToken(t *testing.T) {
	up := NewGRPCAppenderWithOptions("127.0.0.1:9443", time.Second, "dev-token")
	if up.token != "dev-token" {
		t.Fatalf("token = %q", up.token)
	}
}
