package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"google.golang.org/protobuf/encoding/protojson"
)

func (s *Store) ImportState(state State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Agents = nil
	s.Events = nil
	s.Signals = nil
	s.Incidents = nil
	s.Health = map[string]agenthealth.AgentHealth{}
	for _, raw := range state.Agents {
		var msg AgentIdentity
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		msg = msg.Normalized()
		if msg.Valid() {
			s.Agents = append(s.Agents, msg)
		}
	}
	for _, raw := range state.Events {
		msg := &eventv1.CanonicalEvent{}
		if err := protojson.Unmarshal(raw, msg); err != nil {
			return err
		}
		s.Events = append(s.Events, msg)
	}
	for _, raw := range state.Signals {
		msg := &signalv1.Signal{}
		if err := protojson.Unmarshal(raw, msg); err != nil {
			return err
		}
		s.Signals = append(s.Signals, msg)
	}
	for _, raw := range state.Incidents {
		msg := &incidentv1.Incident{}
		if err := protojson.Unmarshal(raw, msg); err != nil {
			return err
		}
		s.Incidents = append(s.Incidents, msg)
	}
	for _, raw := range state.Health {
		var msg agenthealth.AgentHealth
		if err := json.Unmarshal(raw, &msg); err != nil {
			return err
		}
		s.Health[agentHealthKey(msg.TenantID, msg.AgentID)] = msg
	}
	s.Rules = state.Rules
	s.Policies = state.Policies
	s.Assignments = state.Assignments
	s.PolicyAudits = state.PolicyAudits
	s.Responses = state.Responses
	s.ResponseAcks = state.ResponseAcks
	s.Pullbacks = state.Pullbacks
	s.ControlCommands = state.ControlCommands
	s.AgentSessions = state.AgentSessions
	s.Enrollments = state.Enrollments
	s.Artifacts = state.Artifacts
	s.Channels = state.Channels
	s.Certificates = state.Certificates
	s.Unenrollments = state.Unenrollments
	s.Metrics = state.Metrics
	s.RarityBaseline = state.RarityBaseline.Snapshot()
	s.MetricsByTenant = state.MetricsByTenant
	s.RarityByTenant = make(map[string]rarity.Baseline, len(state.RarityByTenant))
	for tenantID, baseline := range state.RarityByTenant {
		s.RarityByTenant[tenantID] = baseline.Snapshot()
	}
	s.TelemetryBatches = make(map[string]TelemetryBatchRecord, len(state.TelemetryBatches))
	for key, batch := range state.TelemetryBatches {
		s.TelemetryBatches[key] = batch
	}
	s.TenantSignals = map[string][]*signalv1.Signal{}
	for tenantID, messages := range state.TenantSignals {
		for _, raw := range messages {
			message := &signalv1.Signal{}
			if err := protojson.Unmarshal(raw, message); err != nil {
				return err
			}
			s.TenantSignals[tenantID] = append(s.TenantSignals[tenantID], message)
		}
	}
	return nil
}

func (s *Store) Save() error {
	s.durableMu.Lock()
	defer s.durableMu.Unlock()
	s.mu.RLock()
	state, err := s.exportStateLocked()
	path := s.path
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if backend != nil {
		return backend.SaveState(ctx, state)
	}
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func (s *Store) persistFileLocked() error {
	if s.backend != nil || s.path == "" {
		return nil
	}
	state, err := s.exportStateLocked()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data)
}

// writeFileAtomic writes data to a temporary file in the destination directory
// and renames it into place, so a crash mid-write cannot leave a partially
// written or corrupt state file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s *Store) ExportState() (State, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exportStateLocked()
}

func (s *Store) RarityBaselineSnapshot() rarity.Baseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RarityBaseline.Snapshot()
}

func (s *Store) ObserveRaritySignals(signals []*signalv1.Signal) rarity.Baseline {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RarityBaseline.Observe(signals)
	return s.RarityBaseline.Snapshot()
}

func (s *Store) ObserveRaritySignalsForTenant(tenantID string, signals []*signalv1.Signal) rarity.Baseline {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RarityByTenant == nil {
		s.RarityByTenant = map[string]rarity.Baseline{}
	}
	baseline := s.RarityByTenant[tenantID]
	baseline.Observe(signals)
	s.RarityByTenant[tenantID] = baseline
	s.RarityBaseline.Observe(signals)
	return baseline.Snapshot()
}

func (s *Store) RarityBaselineSnapshotForTenant(tenantID string) rarity.Baseline {
	baseline, _ := s.RarityBaselineSnapshotForTenantWithError(tenantID)
	return baseline
}

func (s *Store) RarityBaselineSnapshotForTenantWithError(tenantID string) (rarity.Baseline, error) {
	s.mu.RLock()
	backend := s.backend
	ctx := ctxOrBackground(s.baseCtx)
	baseline := s.RarityByTenant[tenantID].Snapshot()
	s.mu.RUnlock()
	if tenantBackend, ok := backend.(TenantRarityBackend); ok {
		return tenantBackend.LoadRarityForTenant(ctx, tenantID)
	}
	return baseline, nil
}

func (s *Store) exportStateLocked() (State, error) {
	var state State
	state.Metrics = s.Metrics
	state.RarityBaseline = s.RarityBaseline.Snapshot()
	state.MetricsByTenant = make(map[string]Metrics, len(s.MetricsByTenant))
	for tenantID, metrics := range s.MetricsByTenant {
		state.MetricsByTenant[tenantID] = metrics
	}
	state.RarityByTenant = make(map[string]rarity.Baseline, len(s.RarityByTenant))
	for tenantID, baseline := range s.RarityByTenant {
		state.RarityByTenant[tenantID] = baseline.Snapshot()
	}
	state.TelemetryBatches = make(map[string]TelemetryBatchRecord, len(s.TelemetryBatches))
	for key, batch := range s.TelemetryBatches {
		state.TelemetryBatches[key] = batch
	}
	for _, enrollment := range s.Enrollments {
		state.Enrollments = append(state.Enrollments, cloneEnrollment(enrollment))
	}
	for _, artifact := range s.Artifacts {
		state.Artifacts = append(state.Artifacts, cloneArtifact(artifact))
	}
	state.Channels = append([]ArtifactChannel(nil), s.Channels...)
	state.Certificates = append([]AgentCertificate(nil), s.Certificates...)
	state.Unenrollments = append([]UnenrollmentRecord(nil), s.Unenrollments...)
	for _, agent := range s.Agents {
		raw, err := json.Marshal(agent)
		if err != nil {
			return State{}, err
		}
		state.Agents = append(state.Agents, raw)
	}
	mo := protojson.MarshalOptions{UseProtoNames: true}
	state.TenantSignals = make(map[string][]json.RawMessage, len(s.TenantSignals))
	for tenantID, signals := range s.TenantSignals {
		for _, signal := range signals {
			raw, err := mo.Marshal(signal)
			if err != nil {
				return State{}, err
			}
			state.TenantSignals[tenantID] = append(state.TenantSignals[tenantID], raw)
		}
	}
	for _, ev := range s.Events {
		raw, err := mo.Marshal(ev)
		if err != nil {
			return State{}, err
		}
		state.Events = append(state.Events, raw)
	}
	for _, sig := range s.Signals {
		raw, err := mo.Marshal(sig)
		if err != nil {
			return State{}, err
		}
		state.Signals = append(state.Signals, raw)
	}
	for _, inc := range s.Incidents {
		raw, err := mo.Marshal(inc)
		if err != nil {
			return State{}, err
		}
		state.Incidents = append(state.Incidents, raw)
	}
	health := make([]agenthealth.AgentHealth, 0, len(s.Health))
	for _, item := range s.Health {
		health = append(health, item)
	}
	sort.Slice(health, func(i, j int) bool {
		if health[i].TenantID == health[j].TenantID {
			return health[i].AgentID < health[j].AgentID
		}
		return health[i].TenantID < health[j].TenantID
	})
	for _, item := range health {
		raw, err := json.Marshal(item)
		if err != nil {
			return State{}, err
		}
		state.Health = append(state.Health, raw)
	}
	state.Rules = append([]policymodel.RuleContent(nil), s.Rules...)
	state.Policies = append([]policymodel.Policy(nil), s.Policies...)
	state.Assignments = append([]policymodel.Assignment(nil), s.Assignments...)
	state.PolicyAudits = append([]policymodel.AuditRecord(nil), s.PolicyAudits...)
	state.Responses = append([]responsemodel.Command(nil), s.Responses...)
	state.ResponseAcks = append([]responsemodel.Ack(nil), s.ResponseAcks...)
	state.Pullbacks = append([]controlmodel.EvidencePullbackRequest(nil), s.Pullbacks...)
	state.ControlCommands = append([]controlmodel.ControlCommand(nil), s.ControlCommands...)
	state.AgentSessions = append([]AgentSession(nil), s.AgentSessions...)
	return state, nil
}
