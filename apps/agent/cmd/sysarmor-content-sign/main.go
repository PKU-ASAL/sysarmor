package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("sysarmor-content-sign", flag.ContinueOnError)
	keyPath := flags.String("key", "", "PKCS#8 Ed25519 private key")
	keyID := flags.String("key-id", "", "content signing key ID")
	inputPath := flags.String("input", "", "unsigned content JSON")
	outputPath := flags.String("output", "", "signed content JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *inputPath == "" || *outputPath == "" {
		return fmt.Errorf("--key, --key-id, --input, and --output are required")
	}
	privateKey, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		return fmt.Errorf("read content input: %w", err)
	}
	envelope, err := agentcontent.Parse(string(raw))
	if err != nil {
		return err
	}
	envelope, err = agentcontent.SignEnvelope(envelope, *keyID, privateKey)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outputPath, append(encoded, '\n'), 0o644); err != nil {
		return fmt.Errorf("write signed content: %w", err)
	}
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read content signing key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("decode content signing key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse content signing key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("content signing key must be Ed25519")
	}
	return privateKey, nil
}
