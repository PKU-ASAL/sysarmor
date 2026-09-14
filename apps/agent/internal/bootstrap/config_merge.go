package bootstrap

import (
	"fmt"
	"os"

	agentconfig "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
)

func MergeReleaseConfig(existingPath, releasePath, outputPath string) error {
	existing, err := os.ReadFile(existingPath)
	if err != nil {
		return fmt.Errorf("read existing config: %w", err)
	}
	release, err := os.ReadFile(releasePath)
	if err != nil {
		return fmt.Errorf("read release config: %w", err)
	}
	merged, err := agentconfig.MergeReleaseContent(existing, release)
	if err != nil {
		return err
	}
	return writePrivateFile(outputPath, merged)
}

func writePrivateFile(path string, content []byte) error {
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open merged config: %w", err)
	}
	if _, err := output.Write(content); err != nil {
		_ = output.Close()
		return fmt.Errorf("write merged config: %w", err)
	}
	return output.Close()
}
