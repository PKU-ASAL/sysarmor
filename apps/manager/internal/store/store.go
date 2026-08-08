package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/analytics/rarity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/migrations"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

type Store struct {
	mu               sync.RWMutex
	durableMu        sync.Mutex
	path             string
	backendInfo      *Info
	backend          Backend
	baseCtx          context.Context
	Agents           []AgentIdentity
	Events           []*eventv1.CanonicalEvent
	Signals          []*signalv1.Signal
	Incidents        []*incidentv1.Incident
	Health           map[string]agenthealth.AgentHealth
	Rules            []policymodel.RuleContent
	Policies         []policymodel.Policy
	Assignments      []policymodel.Assignment
	PolicyAudits     []policymodel.AuditRecord
	Responses        []responsemodel.Command
	ResponseAcks     []responsemodel.Ack
	Pullbacks        []controlmodel.EvidencePullbackRequest
	ControlCommands  []controlmodel.ControlCommand
	AgentSessions    []AgentSession
	Enrollments      []Enrollment
	Artifacts        []Artifact
	Channels         []ArtifactChannel
	Certificates     []AgentCertificate
	Unenrollments    []UnenrollmentRecord
	TenantSignals    map[string][]*signalv1.Signal
	MetricsByTenant  map[string]Metrics
	RarityByTenant   map[string]rarity.Baseline
	TelemetryBatches map[string]TelemetryBatchRecord
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, baseCtx: context.Background(), Health: map[string]agenthealth.AgentHealth{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if err := s.ImportState(state); err != nil {
		return nil, err
	}
	return s, nil
}

// AttachBackend binds a durable persistence Backend to the store. The supplied
// context becomes the base context for all backend operations, so backend work
// is cancelled when this context is done (e.g. on server shutdown). Passing a
// nil context falls back to context.Background().
func (s *Store) AttachBackend(ctx context.Context, backend Backend, info Info) {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backendInfo = &info
	s.backend = backend
	s.baseCtx = ctx
}

func (s *Store) backendCtx() (Backend, context.Context) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend, ctxOrBackground(s.baseCtx)
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (s *Store) Info() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.backendInfo != nil {
		return *s.backendInfo
	}
	backend := "file"
	if s.path == "" {
		backend = "memory"
	}
	return Info{
		Backend:          backend,
		Path:             s.path,
		StateVersion:     FileStoreStateVersion,
		MigrationVersion: FileStoreStateVersion,
		PostgresSchema:   migrations.PostgresVersion,
	}
}
