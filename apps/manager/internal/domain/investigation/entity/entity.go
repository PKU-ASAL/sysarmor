package entity

import (
	"strings"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func Normalize(value domaintelemetry.Entity) domaintelemetry.Entity {
	value.Kind = strings.ToLower(strings.TrimSpace(value.Kind))
	value.Key = strings.TrimSpace(value.Key)
	value.Role = strings.ToLower(strings.TrimSpace(value.Role))
	if knownKind(value.Kind) {
		value.Key = ensurePrefix(value.Key, value.Kind+":")
	}
	return value
}

func Unique(values []domaintelemetry.Entity) []domaintelemetry.Entity {
	seen := make(map[string]struct{}, len(values))
	result := make([]domaintelemetry.Entity, 0, len(values))
	for _, value := range values {
		normalized := Normalize(value)
		if normalized.Kind == "" || normalized.Key == "" {
			continue
		}
		key := normalized.Kind + "\x00" + normalized.Key + "\x00" + normalized.Role
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func knownKind(kind string) bool {
	switch kind {
	case "file", "socket", "process", "container", "user", "token":
		return true
	default:
		return false
	}
}

func ensurePrefix(key, prefix string) string {
	if key == "" || strings.HasPrefix(key, prefix) {
		return key
	}
	return prefix + key
}
