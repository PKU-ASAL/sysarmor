package main

import "testing"

func TestPrepareGatewayDefaultsToProduction(t *testing.T) {
	_, err := prepareGateway(gatewaySecurityConfig{listen: "127.0.0.1:9444"}, false)
	if err == nil {
		t.Fatal("prepareGateway() accepted missing production mTLS")
	}
}

func TestPrepareGatewayUsesDevelopmentOnlyWhenExplicit(t *testing.T) {
	prepared, err := prepareGateway(gatewaySecurityConfig{listen: "127.0.0.1:9444"}, true)
	if err != nil {
		t.Fatalf("prepareGateway() error = %v", err)
	}
	if prepared.MTLSEnabled() {
		t.Fatal("explicit development gateway unexpectedly enabled mTLS")
	}
}
