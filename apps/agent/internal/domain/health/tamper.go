package health

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
)

const SensorTamperSignalName = "sensor_tamper_or_blindness"

type TamperDetector struct {
	activeIncident string
}

type TamperOptions struct {
	MaxRestarts      uint64
	MaxParseErrors   uint64
	MaxDroppedEvents uint64
}

func (d *TamperDetector) Evaluate(health Snapshot, now time.Time, options TamperOptions) *detection.Signal {
	reason := tamperReason(health.Sensor, options)
	if reason == "" {
		d.activeIncident = ""
		return nil
	}
	incident := tamperIncidentKey(health, reason)
	if incident == d.activeIncident {
		return nil
	}
	d.activeIncident = incident
	return tamperSignal(health, reason, tamperSignalID(health, reason, now))
}

func tamperReason(sensor Sensor, options TamperOptions) string {
	switch {
	case !sensor.PolicyLoaded:
		return "policy_not_loaded"
	case !sensor.Running:
		return "sensor_not_running"
	case sensor.LastError != "":
		return "sensor_error:" + sensor.LastError
	case options.MaxRestarts > 0 && sensor.RestartCount > options.MaxRestarts:
		return fmt.Sprintf("restart_count_exceeded:%d>%d", sensor.RestartCount, options.MaxRestarts)
	case options.MaxParseErrors > 0 && sensor.ParseErrors > options.MaxParseErrors:
		return fmt.Sprintf("parse_errors_exceeded:%d>%d", sensor.ParseErrors, options.MaxParseErrors)
	case options.MaxDroppedEvents > 0 && sensor.EventsDropped > options.MaxDroppedEvents:
		return fmt.Sprintf("events_dropped_exceeded:%d>%d", sensor.EventsDropped, options.MaxDroppedEvents)
	default:
		return ""
	}
}

func tamperIncidentKey(health Snapshot, reason string) string {
	return strings.Join([]string{
		health.TenantID, health.AgentID, health.HostID, tamperScope(health),
		health.Sensor.Backend, stableTamperReason(reason),
	}, "|")
}

func stableTamperReason(reason string) string {
	for _, prefix := range []string{"restart_count_exceeded", "parse_errors_exceeded", "events_dropped_exceeded"} {
		if strings.HasPrefix(reason, prefix+":") {
			return prefix
		}
	}
	return reason
}

func tamperSignal(health Snapshot, reason, id string) *detection.Signal {
	entities := tamperEntities(health)
	return &detection.Signal{
		ID: id, Name: SensorTamperSignalName, Where: detection.SignalWhereEndpoint,
		BaseRisk: 90, LocalRarity: 1, GlobalRarity: 1, LineageID: "agent:" + health.AgentID,
		Entities: entities, Terminal: true, Labels: map[string]string{"signal_class": "agent-health"},
		Evidence: &detection.Evidence{ID: "evb-" + id, Entities: entities, Summary: tamperSummary(health, reason)},
	}
}

func tamperEntities(health Snapshot) []detection.Entity {
	entities := []detection.Entity{
		{Kind: "agent", Key: "agent:" + health.AgentID, Role: "subject"},
		{Kind: "host", Key: "host:" + health.HostID, Role: "host"},
		{Kind: "sensor", Key: "sensor:" + firstValue(health.Sensor.Backend, "unknown"), Role: "object"},
	}
	if scope := tamperScope(health); scope != "" {
		entities = append(entities, detection.Entity{Kind: "scope", Key: "scope:" + scope, Role: "scope"})
	}
	return entities
}

func tamperSummary(health Snapshot, reason string) string {
	summary := "sensor tamper/blindness: " + reason
	if scope := tamperScope(health); scope != "" {
		summary += "; scope=" + scope
	}
	summary += fmt.Sprintf("; restarts=%d parse_errors=%d dropped_events=%d events_seen=%d",
		health.Sensor.RestartCount, health.Sensor.ParseErrors, health.Sensor.EventsDropped, health.Sensor.EventsSeen)
	if health.Sensor.LastExitReason != "" {
		summary += "; last_exit=" + health.Sensor.LastExitReason
	}
	return summary
}

func tamperSignalID(health Snapshot, reason string, now time.Time) string {
	base := strings.Join([]string{
		health.TenantID, health.AgentID, health.HostID, tamperScope(health),
		health.Sensor.Backend, reason, fmt.Sprint(now.UTC().UnixNano()),
	}, "|")
	sum := sha256.Sum256([]byte(base))
	return "sig-tamper-" + hex.EncodeToString(sum[:8])
}

func tamperScope(health Snapshot) string {
	scopeType := strings.TrimSpace(health.ScopeType)
	if scopeType == "" {
		return ""
	}
	selector := strings.TrimSpace(health.ScopeSelector)
	if selector == "" {
		return scopeType
	}
	return scopeType + ":" + selector
}

func firstValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
