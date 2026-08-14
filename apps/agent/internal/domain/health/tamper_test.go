package health

import (
	"strings"
	"testing"
	"time"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
)

func TestTamperDetectorEmitsDomainSignalForSensorFailure(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	health := tamperHealth(now)
	signal := (&TamperDetector{}).Evaluate(health, now, TamperOptions{})

	if signal == nil {
		t.Fatal("Evaluate() = nil")
	}
	if signal.Name != SensorTamperSignalName || !signal.Terminal || signal.Where != detection.SignalWhereEndpoint {
		t.Fatalf("signal = %+v", signal)
	}
	if signal.Evidence == nil || !strings.Contains(signal.Evidence.Summary, "scope=container:abc123") {
		t.Fatalf("signal evidence = %+v", signal.Evidence)
	}
}

func TestTamperDetectorSuppressesIncidentUntilRecovery(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	detector := &TamperDetector{}
	health := tamperHealth(now)
	if detector.Evaluate(health, now, TamperOptions{}) == nil {
		t.Fatal("first failure signal = nil")
	}
	if signal := detector.Evaluate(health, now.Add(time.Second), TamperOptions{}); signal != nil {
		t.Fatalf("duplicate signal = %+v", signal)
	}
	health.Sensor.Running = true
	health.Sensor.LastError = ""
	if signal := detector.Evaluate(health, now.Add(2*time.Second), TamperOptions{}); signal != nil {
		t.Fatalf("recovery signal = %+v", signal)
	}
	health.Sensor.Running = false
	if detector.Evaluate(health, now.Add(3*time.Second), TamperOptions{}) == nil {
		t.Fatal("failure after recovery signal = nil")
	}
}

func TestTamperDetectorDoesNotRepeatGrowingThresholdIncident(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	detector := &TamperDetector{}
	health := tamperHealth(now)
	health.Sensor.Running = true
	health.Sensor.LastError = ""
	health.Sensor.ParseErrors = 3
	options := TamperOptions{MaxParseErrors: 2}
	if detector.Evaluate(health, now, options) == nil {
		t.Fatal("first threshold signal = nil")
	}
	health.Sensor.ParseErrors = 4
	if signal := detector.Evaluate(health, now.Add(time.Second), options); signal != nil {
		t.Fatalf("growing threshold repeated signal = %+v", signal)
	}
}

func tamperHealth(now time.Time) Snapshot {
	return Snapshot{
		Runtime: Runtime{
			AgentID: "agent-a", HostID: "host-a", TenantID: "default",
			ScopeType: "container", ScopeSelector: "abc123",
		},
		ObservedAt: now,
		Sensor: Sensor{
			Backend: "tetragon", PolicyLoaded: true, Running: false,
			RestartCount: 4, ParseErrors: 2, EventsDropped: 3,
			EventsSeen: 11, LastExitReason: "exit status 7", LastError: "exit status 7",
		},
	}
}
