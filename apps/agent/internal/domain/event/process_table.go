package event

import "sync"

type Process struct {
	StableID              string
	SensorExecID          string
	PID                   uint32
	PPID                  uint32
	Binary                string
	Argv                  []string
	UID                   uint32
	StartTimeNS           uint64
	ArgvBoundariesTrusted bool
	LineageID             string
}

type ProcessTable struct {
	mu       sync.RWMutex
	byPID    map[uint32]Process
	byStable map[string]Process
	bySensor map[string]Process
}

func NewProcessTable() *ProcessTable {
	return &ProcessTable{
		byPID:    make(map[uint32]Process),
		byStable: make(map[string]Process),
		bySensor: make(map[string]Process),
	}
}

func (table *ProcessTable) Upsert(process Process) {
	table.mu.Lock()
	defer table.mu.Unlock()
	table.byPID[process.PID] = process
	table.byStable[process.StableID] = process
	if process.SensorExecID != "" {
		table.bySensor[process.SensorExecID] = process
	}
}

func (table *ProcessTable) ByPID(pid uint32) (Process, bool) {
	table.mu.RLock()
	defer table.mu.RUnlock()
	process, ok := table.byPID[pid]
	return process, ok
}

func (table *ProcessTable) ByStableID(stableID string) (Process, bool) {
	table.mu.RLock()
	defer table.mu.RUnlock()
	process, ok := table.byStable[stableID]
	return process, ok
}

func (table *ProcessTable) BySensorExecID(execID string) (Process, bool) {
	table.mu.RLock()
	defer table.mu.RUnlock()
	process, ok := table.bySensor[execID]
	return process, ok
}
