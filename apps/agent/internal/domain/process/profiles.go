package process

import (
	"fmt"
	"sync"
	"time"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
)

type Limits struct {
	MaxProfiles, MaxFiles, MaxNetworks, MaxEventRefs int
	ExitGrace, RetainedTTL                           time.Duration
}

type State string

const (
	StateActive   State = "active"
	StateExited   State = "exited"
	StateRetained State = "retained"
)

type IdentityObservation struct {
	HostID, ParentSensorExecID string
	Process                    domainevent.Process
}

type ResolvedIdentity struct {
	Process        domainevent.Process
	ParentStableID string
}

type Snapshot struct {
	StableID, ParentStableID, LineageID, Binary string
	Revision                                    uint64
	State                                       State
	BehaviorCounts                              map[string]uint64
	Files, Networks, EventRefs                  []string
}

type Profile struct {
	process        domainevent.Process
	parentStableID string
	revision       uint64
	behaviorCounts map[string]uint64
	files          boundedValues
	networks       boundedValues
	eventRefs      []string
	state          State
	lastSeenNS     uint64
	exitedAtNS     uint64
}

type Metrics struct {
	Active, Exited, Retained                           uint64
	Compactions, Expired, CapacityEvictions            uint64
	FileEvictions, NetworkEvictions, EventRefEvictions uint64
}

type Profiles struct {
	mu       sync.RWMutex
	limits   Limits
	profiles map[string]*Profile
	byPID    map[uint32]string
	bySensor map[string]string
	metrics  Metrics
}

func NewProfiles(limits Limits) (*Profiles, error) {
	if limits.MaxProfiles <= 0 || limits.MaxFiles <= 0 || limits.MaxNetworks <= 0 || limits.MaxEventRefs <= 0 {
		return nil, fmt.Errorf("process profile limits must be positive")
	}
	return &Profiles{
		limits: limits, profiles: make(map[string]*Profile),
		byPID: make(map[uint32]string), bySensor: make(map[string]string),
	}, nil
}

func (profiles *Profiles) Resolve(observation IdentityObservation) ResolvedIdentity {
	profiles.mu.Lock()
	defer profiles.mu.Unlock()

	process := observation.Process
	process.StableID = domainevent.StableProcessID(observation.HostID, process.PID, process.StartTimeNS)
	if process.SensorExecID != "" {
		process.StableID = domainevent.SensorProcessID(observation.HostID, process.SensorExecID)
	}
	parent := profiles.parent(observation.ParentSensorExecID, process.PPID)
	process.LineageID = process.StableID
	parentStableID := ""
	if parent != nil {
		parentStableID = parent.process.StableID
		if parent.process.LineageID != "" {
			process.LineageID = parent.process.LineageID
		}
	}
	profile := profiles.profiles[process.StableID]
	if profile == nil {
		profiles.evictForCapacity()
		profile = &Profile{
			behaviorCounts: make(map[string]uint64),
			files:          boundedValues{limit: profiles.limits.MaxFiles}, networks: boundedValues{limit: profiles.limits.MaxNetworks},
			state: StateActive,
		}
		profiles.profiles[process.StableID] = profile
	}
	profile.process, profile.parentStableID = cloneProcess(process), parentStableID
	profiles.byPID[process.PID] = process.StableID
	if process.SensorExecID != "" {
		profiles.bySensor[process.SensorExecID] = process.StableID
	}
	return ResolvedIdentity{Process: cloneProcess(process), ParentStableID: parentStableID}
}

func (profiles *Profiles) Observe(event domainevent.Event) Snapshot {
	profiles.mu.Lock()
	defer profiles.mu.Unlock()
	profile := profiles.profiles[event.Subject.StableID]
	if profile == nil {
		return Snapshot{}
	}
	if profile.state == StateRetained {
		return profile.snapshot()
	}
	profile.revision++
	profile.behaviorCounts[event.Behavior]++
	if profile.files.add(event.Object.FilePath) {
		profiles.metrics.FileEvictions++
	}
	if profile.networks.add(event.Object.SocketAddress) {
		profiles.metrics.NetworkEvictions++
	}
	var evicted bool
	profile.eventRefs, evicted = appendBounded(profile.eventRefs, event.ID, profiles.limits.MaxEventRefs)
	if evicted {
		profiles.metrics.EventRefEvictions++
	}
	profile.lastSeenNS = eventTimeNS(event)
	if event.Behavior == domainevent.BehaviorProcessExit {
		profile.state, profile.exitedAtNS = StateExited, profile.lastSeenNS
	}
	return profile.snapshot()
}

func (profiles *Profiles) Sweep(nowNS uint64) {
	profiles.mu.Lock()
	defer profiles.mu.Unlock()
	for stableID, profile := range profiles.profiles {
		switch profile.state {
		case StateExited:
			if elapsed(nowNS, profile.exitedAtNS, profiles.limits.ExitGrace) {
				profile.compact()
				profiles.metrics.Compactions++
			}
		case StateRetained:
			retention := profiles.limits.ExitGrace + profiles.limits.RetainedTTL
			if elapsed(nowNS, profile.exitedAtNS, retention) {
				profiles.remove(stableID, profile)
				profiles.metrics.Expired++
			}
		}
	}
}

func (profiles *Profiles) Metrics() Metrics {
	profiles.mu.RLock()
	defer profiles.mu.RUnlock()
	metrics := profiles.metrics
	for _, profile := range profiles.profiles {
		switch profile.state {
		case StateActive:
			metrics.Active++
		case StateExited:
			metrics.Exited++
		case StateRetained:
			metrics.Retained++
		}
	}
	return metrics
}

func (profiles *Profiles) Snapshot(stableID string) (Snapshot, bool) {
	profiles.mu.RLock()
	defer profiles.mu.RUnlock()
	profile, ok := profiles.profiles[stableID]
	if !ok {
		return Snapshot{}, false
	}
	return profile.snapshot(), true
}

func (profiles *Profiles) parent(sensorID string, pid uint32) *Profile {
	stableID := profiles.bySensor[sensorID]
	if stableID == "" {
		stableID = profiles.byPID[pid]
	}
	return profiles.profiles[stableID]
}

func cloneProcess(process domainevent.Process) domainevent.Process {
	process.Argv = append([]string(nil), process.Argv...)
	return process
}

func (profile *Profile) snapshot() Snapshot {
	return Snapshot{
		StableID: profile.process.StableID, ParentStableID: profile.parentStableID,
		LineageID: profile.process.LineageID, Binary: profile.process.Binary, Revision: profile.revision,
		State:          profile.state,
		BehaviorCounts: cloneCounts(profile.behaviorCounts), Files: append([]string(nil), profile.files.values...),
		Networks: append([]string(nil), profile.networks.values...), EventRefs: append([]string(nil), profile.eventRefs...),
	}
}

func (profile *Profile) compact() {
	profile.state = StateRetained
	profile.behaviorCounts = make(map[string]uint64)
	profile.files.values, profile.networks.values, profile.eventRefs = nil, nil, nil
}

func (profiles *Profiles) remove(stableID string, profile *Profile) {
	delete(profiles.profiles, stableID)
	if profiles.byPID[profile.process.PID] == stableID {
		delete(profiles.byPID, profile.process.PID)
	}
	if profiles.bySensor[profile.process.SensorExecID] == stableID {
		delete(profiles.bySensor, profile.process.SensorExecID)
	}
}

func (profiles *Profiles) evictForCapacity() {
	if len(profiles.profiles) < profiles.limits.MaxProfiles {
		return
	}
	stableID, profile := profiles.capacityVictim()
	if profile != nil {
		profiles.remove(stableID, profile)
		profiles.metrics.CapacityEvictions++
	}
}

func (profiles *Profiles) capacityVictim() (string, *Profile) {
	var selectedID string
	var selected *Profile
	for stableID, profile := range profiles.profiles {
		if selected == nil || profileLess(stableID, profile, selectedID, selected) {
			selectedID, selected = stableID, profile
		}
	}
	return selectedID, selected
}

func profileLess(stableID string, profile *Profile, selectedID string, selected *Profile) bool {
	if stateRank(profile.state) != stateRank(selected.state) {
		return stateRank(profile.state) < stateRank(selected.state)
	}
	if profile.lastSeenNS != selected.lastSeenNS {
		return profile.lastSeenNS < selected.lastSeenNS
	}
	return stableID < selectedID
}

func stateRank(state State) int {
	switch state {
	case StateRetained:
		return 0
	case StateExited:
		return 1
	default:
		return 2
	}
}

func elapsed(nowNS, sinceNS uint64, duration time.Duration) bool {
	return duration >= 0 && nowNS >= sinceNS+uint64(duration)
}

func eventTimeNS(event domainevent.Event) uint64 {
	if event.OccurredAtNS != 0 {
		return event.OccurredAtNS
	}
	return event.MonoNS
}

type boundedValues struct {
	limit  int
	values []string
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
