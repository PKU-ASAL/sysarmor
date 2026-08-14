package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func LoadFile(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	cfg, err := parse(f)
	if err != nil {
		return Config{}, err
	}
	cfg.Sensor.PolicyPath = cfg.Policy.Path
	return cfg, cfg.Validate()
}

func parse(r io.Reader) (Config, error) {
	cfg := defaults()
	scanner := bufio.NewScanner(r)
	root, nested := "", ""
	seen := make(map[string]struct{})
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := stripComment(scanner.Text())
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		trimmed := strings.TrimSpace(raw)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			root = strings.TrimSuffix(trimmed, ":")
			if err := markConfigPath(seen, "section "+root); err != nil {
				return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
			}
			nested = ""
			continue
		}
		if root == "" {
			return Config{}, fmt.Errorf("line %d: key outside section", lineNo)
		}
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			nested = root + "." + strings.TrimSuffix(trimmed, ":")
			if err := markConfigPath(seen, "section "+nested); err != nil {
				return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
			}
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected key: value", lineNo)
		}
		key = strings.TrimSpace(key)
		section := root
		if indent >= 4 && nested != "" {
			section = nested
		} else if indent == 2 {
			nested = ""
		}
		if err := markConfigPath(seen, "key "+section+"."+key); err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := assign(&cfg, section, key, unquote(strings.TrimSpace(value))); err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func markConfigPath(seen map[string]struct{}, path string) error {
	if _, ok := seen[path]; ok {
		return fmt.Errorf("duplicate %s", path)
	}
	seen[path] = struct{}{}
	return nil
}

func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
		return value[1 : len(value)-1]
	}
	return value
}
