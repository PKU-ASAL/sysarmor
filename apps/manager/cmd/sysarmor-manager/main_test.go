package main

import (
	"database/sql"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestManagerConfiguresTelemetryApplicationRoutes(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "bootstrap.NewManagerTelemetryHTTP") || !strings.Contains(text, "SetTelemetryRoutes") ||
		!strings.Contains(text, "bootstrap.NewManagerSearchHTTP") || !strings.Contains(text, "SetSearchRoutes") {
		t.Fatal("manager main does not configure telemetry and search application routes")
	}
}

func TestManagerConfiguresOverviewApplicationRoute(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "bootstrap.NewManagerOverviewHTTP") || !strings.Contains(text, "SetOverviewRoutes") {
		t.Fatal("manager main does not configure overview application route")
	}
}

func TestManagerConfiguresStatusRoutes(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "bootstrap.NewManagerStatusHTTP") || !strings.Contains(text, "SetStatusRoutes") {
		t.Fatal("manager main does not configure status routes")
	}
}

func TestManagerEnrollmentConfigUsesEnvironment(t *testing.T) {
	t.Setenv("SYSARMOR_AGENT_CA_CERT", "/tmp/agent-ca.crt")
	t.Setenv("SYSARMOR_AGENT_CA_KEY", "/tmp/agent-ca.key")
	t.Setenv("SYSARMOR_TRUST_DOMAIN", "tenant.example")
	t.Setenv("SYSARMOR_PUBLIC_URL", "https://manager.example/base")
	t.Setenv("SYSARMOR_ARTIFACT_PUBLIC_KEY", "/tmp/artifact-public.pem")
	t.Setenv("SYSARMOR_ARTIFACT_DIR", "/var/lib/sysarmor/artifacts")
	t.Setenv("SYSARMOR_DEPLOY_GATEWAY_ADDR", "gateway.example:9444")
	t.Setenv("SYSARMOR_DEPLOY_GATEWAY_SNI", "gateway.example")
	t.Setenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL", "https://downloads.example/releases")
	db := &sql.DB{}

	config := managerEnrollmentConfig(db)
	if config.DB != db || config.CACertFile != "/tmp/agent-ca.crt" || config.CAKeyFile != "/tmp/agent-ca.key" ||
		config.TrustDomain != "tenant.example" || config.PublicURL != "https://manager.example/base" ||
		config.ArtifactPublicKeyFile != "/tmp/artifact-public.pem" || config.ArtifactDir != "/var/lib/sysarmor/artifacts" ||
		config.DeployGatewayAddress != "gateway.example:9444" || config.DeployGatewayServerName != "gateway.example" ||
		config.PackageDownloadBaseURL != "https://downloads.example/releases" {
		t.Fatalf("enrollment config = %#v", config)
	}
}

func TestManagerEnrollmentConfigUsesDefaultArtifactDir(t *testing.T) {
	t.Setenv("SYSARMOR_ARTIFACT_DIR", "")
	config := managerEnrollmentConfig(&sql.DB{})
	if config.ArtifactDir != "/var/lib/sysarmor/manager/artifacts" {
		t.Fatalf("artifact dir = %q", config.ArtifactDir)
	}
}

func TestManagerArtifactConfigUsesEnvironment(t *testing.T) {
	t.Setenv("SYSARMOR_ARTIFACT_PUBLIC_KEY", "/tmp/artifact-public.pem")
	t.Setenv("SYSARMOR_ARTIFACT_DIR", "/var/lib/sysarmor/artifacts")
	db := &sql.DB{}

	config := managerArtifactConfig(db)
	if config.DB != db || config.ArtifactPublicKeyFile != "/tmp/artifact-public.pem" ||
		config.ArtifactDir != "/var/lib/sysarmor/artifacts" || config.Resolve == nil {
		t.Fatalf("artifact config = %#v", config)
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
