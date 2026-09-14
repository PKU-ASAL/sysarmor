package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
)

func TestRunSignsContentForStoreValidation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "content-key.pem")
	inputPath := filepath.Join(dir, "input.json")
	outputPath := filepath.Join(dir, "output.json")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	input := `{"api_version":"sysarmor.content/v1","kind":"contextset","metadata":{"id":"ctx:test","version":"v1"},"spec":{"value_type":"string","values":["value"]}}`
	if err := os.WriteFile(inputPath, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"--key", keyPath, "--key-id", "release-test", "--input", inputPath, "--output", outputPath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := agentcontent.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	store, err := agentcontent.NewStoreWithOptions(agentcontent.Options{TrustedKeys: map[string]ed25519.PublicKey{"release-test": publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Validate(envelope, false); err != nil {
		t.Fatalf("signed content validation failed: %v", err)
	}
}
