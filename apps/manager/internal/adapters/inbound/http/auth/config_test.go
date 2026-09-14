package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthConfigRejectsIncompleteInternalIssuer(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Issuer: "sysarmor-bff", Audience: "sysarmor-manager"},
		{PublicKeyFile: "public.pem", Audience: "sysarmor-manager"},
		{PublicKeyFile: "public.pem", Issuer: "sysarmor-bff"},
	} {
		if _, err := NewVerifier(context.Background(), cfg); err == nil {
			t.Fatalf("NewVerifier(%+v) error=nil", cfg)
		}
	}
}

func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestAuthConfigReadsInternalIssuerPublicKey(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(keyFile, testPublicKeyPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewVerifier(context.Background(), Config{
		PublicKeyFile: keyFile,
		Issuer:        "sysarmor-bff",
		Audience:      "sysarmor-manager",
	})
	if err != nil || strings.TrimSpace(keyFile) == "" {
		t.Fatalf("error=%v", err)
	}
}
