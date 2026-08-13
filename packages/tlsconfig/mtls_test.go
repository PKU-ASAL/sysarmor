package tlsconfig

import (
	"strings"
	"testing"
)

func TestMTLSServerOptionRequiresClientCA(t *testing.T) {
	_, err := MTLSServerOption("server.pem", "server-key.pem", "")
	if err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("MTLSServerOption() error = %v, want missing client CA error", err)
	}
}

func TestMTLSServerOptionRequiresServerCertificateAndKey(t *testing.T) {
	tests := []struct {
		name string
		cert string
		key  string
	}{
		{name: "missing certificate", key: "server-key.pem"},
		{name: "missing key", cert: "server.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := MTLSServerOption(tt.cert, tt.key, "ca.pem")
			if err == nil || !strings.Contains(err.Error(), "cert and key") {
				t.Fatalf("MTLSServerOption() error = %v, want missing cert/key error", err)
			}
		})
	}
}
