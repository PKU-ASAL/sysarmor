package bootstrap

import (
	"strings"
	"testing"
)

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
