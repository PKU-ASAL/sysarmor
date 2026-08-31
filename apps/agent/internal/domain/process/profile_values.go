package process

import "time"

import domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"

type boundedValues struct {
	limit  int
	values []string
}

func eventTimeNS(event domainevent.Event) uint64 {
	if event.OccurredAtNS != 0 {
		return event.OccurredAtNS
	}
	return event.MonoNS
}

func (values *boundedValues) add(value string) bool {
	if value == "" || contains(values.values, value) {
		return false
	}
	var evicted bool
	values.values, evicted = appendBounded(values.values, value, values.limit)
	return evicted
}

func appendBounded(values []string, value string, limit int) ([]string, bool) {
	if value == "" {
		return values, false
	}
	values = append(values, value)
	if len(values) > limit {
		return values[len(values)-limit:], true
	}
	return values, false
}

func elapsed(nowNS, sinceNS uint64, duration time.Duration) bool {
	return duration >= 0 && nowNS >= sinceNS+uint64(duration)
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

func cloneCounts(values map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneLabels(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
