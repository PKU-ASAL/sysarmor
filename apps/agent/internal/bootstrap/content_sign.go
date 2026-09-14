package bootstrap

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
)

type ContentSignOptions struct {
	KeyPath    string
	KeyID      string
	InputPath  string
	OutputPath string
}

func SignContent(options ContentSignOptions) error {
	privateKey, err := readPrivateKey(options.KeyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(options.InputPath)
	if err != nil {
		return fmt.Errorf("read content input: %w", err)
	}
	envelope, err := agentcontent.Parse(string(raw))
	if err != nil {
		return err
	}
	envelope, err = agentcontent.SignEnvelope(envelope, options.KeyID, privateKey)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(options.OutputPath, append(encoded, '\n'), 0o644); err != nil {
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
