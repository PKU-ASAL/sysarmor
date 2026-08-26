package bootstrap

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
)

func TestNewGatewayRejectsMissingRuntimeDependencies(t *testing.T) {
	_, _, err := NewGateway(context.Background(), GatewayRuntimeConfig{Listen: "127.0.0.1:9444"})
	if err == nil || !strings.Contains(err.Error(), "postgres dsn") {
		t.Fatalf("NewGateway() error = %v, want missing postgres dsn", err)
	}
}

func TestGatewayRuntimeConfigRequiresKafkaBrokers(t *testing.T) {
	config := validGatewayRuntimeConfig()
	config.KafkaBrokers = nil
	if err := config.validate(); err == nil || !strings.Contains(err.Error(), "kafka brokers") {
		t.Fatalf("validate() error = %v, want missing kafka brokers", err)
	}
}

func TestGatewayMetricsExposeBatchPublishBoundary(t *testing.T) {
	metrics := &gatewayapp.BatchMetrics{}
	server := newGatewayHealthServer("127.0.0.1:0", true, metrics)
	request := httptest.NewRequest("GET", "/metrics", nil)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["batches_received"]; !ok {
		t.Fatalf("metrics=%v", got)
	}
}

func TestGatewayRunCoordinatesListenerFailures(t *testing.T) {
	source, err := os.ReadFile("gateway_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"grpcErrors", "healthErrors", "runtime.stop()"} {
		if !strings.Contains(text, required) {
			t.Fatalf("Gateway Run must coordinate listener failures through %q", required)
		}
	}
	if !strings.Contains(text, "select {") {
		t.Fatal("Gateway Run must coordinate gRPC and health listener errors")
	}
}

func TestGatewayConnectsToControlDatabaseWithoutOwningMigrations(t *testing.T) {
	source, err := os.ReadFile("gateway_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "OpenPostgresConnection") {
		t.Fatal("gateway must connect through the non-migrating postgres path")
	}
	if strings.Contains(text, "OpenPostgres(ctx, config.PostgresDriver") {
		t.Fatal("gateway must not run control-plane migrations")
	}
}

func TestGatewayStopHasGracefulShutdownDeadline(t *testing.T) {
	source, err := os.ReadFile("gateway_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "GracefulStop()") || !strings.Contains(text, "runtime.grpcServer.Stop()") {
		t.Fatal("Gateway stop must force-stop after graceful shutdown deadline")
	}
	if !strings.Contains(text, "3*time.Second") {
		t.Fatal("Gateway stop must define a bounded graceful shutdown deadline")
	}
}

func validGatewayRuntimeConfig() GatewayRuntimeConfig {
	return GatewayRuntimeConfig{
		Listen: "127.0.0.1:9444", Development: true,
		PostgresDriver: "postgres", PostgresDSN: "postgres://database",
		KafkaBrokers: []string{"kafka:9092"},
	}
}

func TestProductionGatewayRejectsMissingMTLS(t *testing.T) {
	_, err := NewProductionGateway(GatewayConfig{Listen: ":9444"})
	if err == nil || !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("NewProductionGateway() error = %v, want missing mTLS error", err)
	}
}

func TestProductionGatewayRequiresClientCA(t *testing.T) {
	_, err := NewProductionGateway(GatewayConfig{
		Listen:  ":9444",
		TLSCert: "server.pem",
		TLSKey:  "server-key.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("NewProductionGateway() error = %v, want missing client CA error", err)
	}
}

func TestDevelopmentGatewayRejectsNonLoopbackInsecureListen(t *testing.T) {
	addresses := []string{"0.0.0.0:9444", "[::]:9444", ":9444", "192.0.2.1:9444"}
	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			_, err := NewDevelopmentGateway(GatewayConfig{Listen: address})
			if err == nil || !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("NewDevelopmentGateway() error = %v, want loopback error", err)
			}
		})
	}
}

func TestDevelopmentGatewayAllowsLoopbackInsecureListen(t *testing.T) {
	addresses := []string{"localhost:9444", "127.0.0.1:9444", "127.12.34.56:9444", "[::1]:9444"}
	for _, address := range addresses {
		t.Run(address, func(t *testing.T) {
			gateway, err := NewDevelopmentGateway(GatewayConfig{Listen: address})
			if err != nil {
				t.Fatalf("NewDevelopmentGateway() error = %v", err)
			}
			if gateway.MTLSEnabled() {
				t.Fatal("development gateway unexpectedly enabled mTLS")
			}
		})
	}
}

func TestDevelopmentGatewayRejectsTLSConfiguration(t *testing.T) {
	_, err := NewDevelopmentGateway(GatewayConfig{
		Listen:  "127.0.0.1:9444",
		TLSCert: "server.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "development") {
		t.Fatalf("NewDevelopmentGateway() error = %v, want ambiguous development TLS error", err)
	}
}

func TestGatewayControlPlaneRejectsMissingDatabase(t *testing.T) {
	server, err := NewGatewayControlPlane(ControlPlaneConfig{})
	if err == nil || server != nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("server=%v error=%v", server, err)
	}
}
