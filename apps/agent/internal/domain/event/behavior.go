package event

import "strings"

func NormalizeBehavior(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}
