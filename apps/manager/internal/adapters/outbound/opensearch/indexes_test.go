package opensearch

import "testing"

func TestStableReadAndWriteAliases(t *testing.T) {
	want := map[string]string{
		"events-read":     "sysarmor-events-read",
		"events-write":    "sysarmor-events-write",
		"signals-read":    "sysarmor-signals-read",
		"signals-write":   "sysarmor-signals-write",
		"incidents-read":  "sysarmor-incidents-read",
		"incidents-write": "sysarmor-incidents-write",
		"evidence-read":   "sysarmor-evidence-read",
		"evidence-write":  "sysarmor-evidence-write",
	}
	got := map[string]string{
		"events-read": EventsReadAlias, "events-write": EventsWriteAlias,
		"signals-read": SignalsReadAlias, "signals-write": SignalsWriteAlias,
		"incidents-read": IncidentsReadAlias, "incidents-write": IncidentsWriteAlias,
		"evidence-read": EvidenceReadAlias, "evidence-write": EvidenceWriteAlias,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("%s=%q, want %q", name, got[name], expected)
		}
	}
}
