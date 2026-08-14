package config

import (
	"bytes"
	"fmt"
	"strings"
)

func MergeReleaseContent(existing, release []byte) ([]byte, error) {
	existingConfig, err := parseValidConfig(existing, "existing")
	if err != nil {
		return nil, err
	}
	releaseConfig, err := parseValidConfig(release, "release")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(releaseConfig.Content.DefaultPath) == "" || strings.TrimSpace(releaseConfig.Content.TrustKeys) == "" {
		return nil, fmt.Errorf("release content.default_path and content.trust_keys are required")
	}
	content := ContentConfig{DefaultPath: releaseConfig.Content.DefaultPath, Path: existingConfig.Content.Path, TrustKeys: releaseConfig.Content.TrustKeys}
	merged := replaceTopLevelSection(string(existing), "content", renderContentConfig(content))
	if _, err := parseValidConfig([]byte(merged), "merged"); err != nil {
		return nil, err
	}
	return []byte(merged), nil
}

func parseValidConfig(raw []byte, name string) (Config, error) {
	cfg, err := parse(bytes.NewReader(raw))
	if err != nil {
		return Config{}, fmt.Errorf("parse %s config: %w", name, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate %s config: %w", name, err)
	}
	return cfg, nil
}

func renderContentConfig(content ContentConfig) string {
	return fmt.Sprintf("content:\n  default_path: %q\n  path: %q\n  trust_keys: %q\n", content.DefaultPath, content.Path, content.TrustKeys)
}

func replaceTopLevelSection(raw, section, replacement string) string {
	lines := strings.Split(raw, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(stripComment(line))
		if start < 0 && line == strings.TrimLeft(line, " \t") && trimmed == section+":" {
			start = i
			continue
		}
		if start >= 0 && i > start && trimmed != "" && line == strings.TrimLeft(line, " \t") {
			end = i
			break
		}
	}
	if start < 0 {
		return strings.TrimRight(raw, "\n") + "\n\n" + replacement
	}
	before := strings.Join(lines[:start], "\n")
	after := strings.Join(lines[end:], "\n")
	return strings.TrimRight(before, "\n") + "\n" + replacement + strings.TrimLeft(after, "\n")
}
