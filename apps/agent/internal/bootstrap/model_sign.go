package bootstrap

import (
	"fmt"
	"os"

	detectionadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
)

type ModelSignOptions struct {
	KeyPath    string
	KeyID      string
	InputPath  string
	OutputPath string
}

func SignLearningModel(options ModelSignOptions) error {
	privateKey, err := readPrivateKey(options.KeyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(options.InputPath)
	if err != nil {
		return fmt.Errorf("read model input: %w", err)
	}
	signed, err := detectionadapter.SignModelBundle(raw, options.KeyID, privateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(options.OutputPath, signed, 0o644); err != nil {
		return fmt.Errorf("write signed model: %w", err)
	}
	return nil
}
