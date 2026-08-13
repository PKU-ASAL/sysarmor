package detection

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/matcher"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestRuleEngineEffectivenessScenarios(t *testing.T) {
	tests := []struct {
		name              string
		events            []*eventv1.CanonicalEvent
		wantSignals       []string
		wantTerminal      string
		forbidSignals     []string
		forbidTerminalAny bool
	}{
		{
			name:         "apt-fileless-c2",
			events:       filelessC2Events(),
			wantSignals:  []string{"download_by_lolbin", "payload_dropped", "payload_lifecycle", "reverse_shell_pattern"},
			wantTerminal: "reverse_shell_pattern",
		},
		{
			name:         "apt-fileless-c2-reordered",
			events:       filelessC2EventsReordered(),
			wantSignals:  []string{"download_by_lolbin", "payload_dropped", "payload_lifecycle", "reverse_shell_pattern"},
			wantTerminal: "reverse_shell_pattern",
		},
		{
			name:              "apt-staged-drop",
			events:            stagedDropEvents(),
			wantSignals:       []string{"payload_dropped"},
			forbidTerminalAny: true,
		},
		{
			name:              "benign-ci-noise",
			events:            benignCINoiseEvents(),
			forbidSignals:     []string{"download_by_lolbin", "payload_dropped", "reverse_shell_pattern", "payload_lifecycle", "suspicious_exec_connect"},
			forbidTerminalAny: true,
		},
	}

	for _, strategy := range []matcher.Strategy{matcher.StrategyLinear, matcher.StrategyOptimized} {
		t.Run(string(strategy), func(t *testing.T) {
			matcher.SetDefaultStrategy(strategy)
			t.Cleanup(func() { matcher.SetDefaultStrategy(matcher.StrategyLinear) })
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					engine, report := newTestEngine(t)
					if report.Status != "applied" {
						t.Fatalf("report = %+v", report)
					}
					signals := processAll(engine, tt.events)
					for _, name := range tt.wantSignals {
						if countSignals(signals, name) == 0 {
							t.Fatalf("missing signal %q; got %v", name, signalSummary(signals))
						}
					}
					if tt.wantTerminal != "" && countTerminalSignals(signals, tt.wantTerminal) == 0 {
						t.Fatalf("missing terminal signal %q; got %v", tt.wantTerminal, signalSummary(signals))
					}
					for _, name := range tt.forbidSignals {
						if countSignals(signals, name) != 0 {
							t.Fatalf("forbidden signal %q emitted; got %v", name, signalSummary(signals))
						}
					}
					if tt.forbidTerminalAny && countAnyTerminalSignals(signals) != 0 {
						t.Fatalf("forbidden terminal signal emitted; got %v", signalSummary(signals))
					}
				})
			}
		})
	}
}

func processAll(engine *Engine, events []*eventv1.CanonicalEvent) []*signalv1.Signal {
	var out []*signalv1.Signal
	for _, ev := range events {
		out = append(out, processWire(engine, ev)...)
	}
	return out
}

func countTerminalSignals(signals []*signalv1.Signal, name string) int {
	count := 0
	for _, sig := range signals {
		if sig.GetName() == name && sig.GetTerminal() {
			count++
		}
	}
	return count
}

func countAnyTerminalSignals(signals []*signalv1.Signal) int {
	count := 0
	for _, sig := range signals {
		if sig.GetTerminal() {
			count++
		}
	}
	return count
}

func signalSummary(signals []*signalv1.Signal) map[string]int {
	out := make(map[string]int)
	for _, sig := range signals {
		name := sig.GetName()
		if sig.GetTerminal() {
			name += ":terminal"
		}
		out[name]++
	}
	return out
}

func filelessC2Events() []*eventv1.CanonicalEvent {
	return []*eventv1.CanonicalEvent{
		connectEventWithParent("fileless-download", "lin-fileless", "curl-fileless", "shell-fileless", "/usr/bin/curl", "10.66.0.99:8080"),
		writeEvent("fileless-write", "lin-fileless", "curl-fileless", "/usr/bin/curl", "/dev/shm/x.sh"),
		execEvent("fileless-exec", "lin-fileless", "payload-fileless", "shell-fileless", "/dev/shm/x.sh", nil),
		connectEventWithParent("fileless-c2", "lin-fileless", "payload-fileless", "shell-fileless", "/bin/bash", "10.66.0.99:443"),
		openEvent("fileless-cred", "lin-fileless", "payload-fileless", "/bin/cat", "/root/.ssh/id_rsa"),
	}
}

func filelessC2EventsReordered() []*eventv1.CanonicalEvent {
	return []*eventv1.CanonicalEvent{
		connectEventWithParent("fileless-download", "lin-fileless", "curl-fileless", "shell-fileless", "/usr/bin/curl", "10.66.0.99:8080"),
		writeEvent("fileless-write", "lin-fileless", "curl-fileless", "/usr/bin/curl", "/dev/shm/x.sh"),
		connectEventWithParent("fileless-c2", "lin-fileless", "payload-fileless", "shell-fileless", "/bin/bash", "10.66.0.99:443"),
		execEvent("fileless-exec", "lin-fileless", "payload-fileless", "shell-fileless", "/usr/bin/bash", []string{"/usr/bin/bash", "/dev/shm/x.sh"}),
		openEvent("fileless-cred", "lin-fileless", "payload-fileless", "/bin/cat", "/root/.ssh/id_rsa"),
	}
}

func stagedDropEvents() []*eventv1.CanonicalEvent {
	return []*eventv1.CanonicalEvent{
		connectEventWithParent("staged-download", "lin-staged-download", "curl-staged", "shell-staged", "/usr/bin/curl", "10.66.0.99:8080"),
		writeEvent("staged-write", "lin-staged-download", "curl-staged", "/usr/bin/curl", "/var/lib/app/plugins/helper"),
		execEvent("staged-exec", "lin-staged-run", "helper-staged", "systemd-staged", "/var/lib/app/plugins/helper", nil),
		connectEventWithParent("staged-report", "lin-staged-run", "helper-staged", "systemd-staged", "/var/lib/app/plugins/helper", "10.66.0.99:443"),
	}
}

func benignCINoiseEvents() []*eventv1.CanonicalEvent {
	return []*eventv1.CanonicalEvent{
		execEvent("ci-build", "lin-ci", "build-ci", "runner-ci", "/usr/bin/make", []string{"test"}),
		writeEvent("ci-artifact", "lin-ci", "build-ci", "/usr/bin/make", "/home/ci/workspace/sysarmor-ci-artifact/app.o"),
		connectEventWithParent("ci-fetch", "lin-ci", "curl-ci", "build-ci", "/usr/bin/curl", "198.51.100.25:80"),
		openEvent("ci-cache", "lin-ci", "build-ci", "/usr/bin/cat", "/home/ci/.cache/sysarmor-ci/index"),
	}
}
