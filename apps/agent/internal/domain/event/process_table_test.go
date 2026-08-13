package event

import (
	"reflect"
	"testing"
)

func TestProcessTableIndexesProcessIdentity(t *testing.T) {
	table := NewProcessTable()
	process := Process{StableID: "stable-a", SensorExecID: "exec-a", PID: 42, LineageID: "lineage-a"}
	table.Upsert(process)

	for name, lookup := range map[string]func() (Process, bool){
		"pid":       func() (Process, bool) { return table.ByPID(42) },
		"stable id": func() (Process, bool) { return table.ByStableID("stable-a") },
		"sensor id": func() (Process, bool) { return table.BySensorExecID("exec-a") },
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := lookup()
			if !ok || !reflect.DeepEqual(got, process) {
				t.Fatalf("lookup = %+v, %t", got, ok)
			}
		})
	}
}
