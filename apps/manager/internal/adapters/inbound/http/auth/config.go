package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	PublicKeyFile string
	Issuer        string
	Audience      string
}

func NewVerifier(_ context.Context, cfg Config) (*Verifier, error) {
	if strings.TrimSpace(cfg.PublicKeyFile) == "" {
		return nil, fmt.Errorf("JWT public key file is required")
	}
	publicKey, err := os.ReadFile(cfg.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read JWT public key: %w", err)
	}
	return NewVerifierPEM(publicKey, cfg.Issuer, cfg.Audience)
}
