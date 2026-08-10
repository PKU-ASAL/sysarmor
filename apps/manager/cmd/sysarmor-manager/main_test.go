package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/backend"
)

func TestManagerEnrollmentConfigUsesEnvironment(t *testing.T) {
	t.Setenv("SYSARMOR_AGENT_CA_CERT", "/tmp/agent-ca.crt")
	t.Setenv("SYSARMOR_AGENT_CA_KEY", "/tmp/agent-ca.key")
	t.Setenv("SYSARMOR_TRUST_DOMAIN", "tenant.example")
	db := &sql.DB{}

	config := managerEnrollmentConfig(db)
	if config.DB != db || config.CACertFile != "/tmp/agent-ca.crt" || config.CAKeyFile != "/tmp/agent-ca.key" || config.TrustDomain != "tenant.example" {
		t.Fatalf("enrollment config = %#v", config)
	}
}

func TestNewManagerHTTPServerConfiguresTimeouts(t *testing.T) {
	server := newManagerHTTPServer(":0", http.NewServeMux())

	if server.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout = %s, want positive", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout = %s, want positive", server.ReadTimeout)
	}
	if server.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout = %s, want positive", server.WriteTimeout)
	}
	if server.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout = %s, want positive", server.IdleTimeout)
	}
}

func TestManagerServerSecurityProfileFollowsStoreBackend(t *testing.T) {
	t.Setenv("SYSARMOR_ARTIFACT_PUBLIC_KEY", "")
	t.Setenv("SYSARMOR_AGENT_CA_CERT", "")
	t.Setenv("SYSARMOR_AGENT_CA_KEY", "")

	if _, err := managerServerForBackend(backend.KindMemory, &store.Store{}, nil); err != nil {
		t.Fatalf("memory manager server error = %v", err)
	}
	if _, err := managerServerForBackend(backend.KindPostgres, &store.Store{}, nil); err == nil || !strings.Contains(err.Error(), "SYSARMOR_ARTIFACT_PUBLIC_KEY") {
		t.Fatalf("postgres manager server error = %v, want production security requirement", err)
	}
}
