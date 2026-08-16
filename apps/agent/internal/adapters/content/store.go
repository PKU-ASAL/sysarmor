package content

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type Envelope struct {
	APIVersion string          `json:"api_version"`
	Kind       string          `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       json.RawMessage `json:"spec"`
	Integrity  Integrity       `json:"integrity,omitempty"`
}

type Metadata struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	TenantID  string `json:"tenant_id,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	TTL       string `json:"ttl,omitempty"`
}

type Integrity struct {
	DigestAlg    string `json:"digest_alg,omitempty"`
	Digest       string `json:"digest,omitempty"`
	SignatureAlg string `json:"signature_alg,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

type Options struct {
	DefaultDir  string
	Dir         string
	TrustedKeys map[string]ed25519.PublicKey
}

type Record struct {
	Ref     string
	Kind    string
	Version string
	Digest  string
	Signed  bool
	Status  string
	RawJSON string
}

type Snapshot struct {
	RulePacks              map[string]Record
	Rules                  []Rule
	ContextSets            map[string]ValueSet
	IOCPacks               map[string]ValueSet
	DefaultManifestVersion string
}

type ValueSet struct {
	Ref       string
	Version   string
	Digest    string
	ValueType string
	Values    []string
}

type Rule struct {
	RuleID         string
	Version        uint64
	RuleSetRef     string
	Severity       string
	RuntimeType    string
	RuntimeEntry   string
	Expr           RuntimeExpr
	Sequence       RuntimeSequence
	Correlate      RuntimeCorrelate
	Suppression    RuntimeSuppression
	RequiredEvents []RequiredEvent
	ContextRefs    []string
	IOCRefs        []string
	ResponseIntent ResponseIntent
	Stage          SignalStage
}

type SignalStage string

const (
	SignalStageCandidate  SignalStage = "candidate"
	SignalStageConclusion SignalStage = "conclusion"
)

type RuntimeExpr struct {
	Conditions     []RuntimeCondition    `json:"conditions"`
	ConditionGroup *RuntimeConditionNode `json:"condition_group,omitempty"`
}

type RuntimeConditionNode struct {
	All       []RuntimeConditionNode `json:"all,omitempty"`
	Any       []RuntimeConditionNode `json:"any,omitempty"`
	Not       *RuntimeConditionNode  `json:"not,omitempty"`
	Condition *RuntimeCondition      `json:"condition,omitempty"`
}

type RuntimeSequence struct {
	Within string        `json:"within"`
	By     []string      `json:"by"`
	Steps  []RuntimeStep `json:"steps"`
}

type RuntimeCorrelate struct {
	Within string        `json:"within"`
	By     []string      `json:"by"`
	Facts  []RuntimeFact `json:"facts"`
}

type RuntimeFact struct {
	ID             string                `json:"id"`
	Event          string                `json:"event,omitempty"`
	Events         []string              `json:"events,omitempty"`
	Conditions     []RuntimeCondition    `json:"conditions"`
	ConditionGroup *RuntimeConditionNode `json:"condition_group,omitempty"`
}

type RuntimeSuppression struct {
	Within string   `json:"within"`
	By     []string `json:"by"`
}

type RuntimeStep struct {
	ID             string                `json:"id"`
	Behavior       string                `json:"behavior,omitempty"`
	Event          string                `json:"event,omitempty"`
	Conditions     []RuntimeCondition    `json:"conditions"`
	ConditionGroup *RuntimeConditionNode `json:"condition_group,omitempty"`
}

type RuntimeCondition struct {
	Field     string   `json:"field"`
	Op        string   `json:"op"`
	Value     string   `json:"value,omitempty"`
	Values    []string `json:"values,omitempty"`
	Ref       string   `json:"ref,omitempty"`
	Step      string   `json:"step,omitempty"`
	StepField string   `json:"step_field,omitempty"`
}

type RequiredEvent struct {
	Behavior string
	Fields   []string
}

type ResponseIntent struct {
	Action     string
	Confidence uint32
	Reason     string
}

type Store struct {
	mu              sync.RWMutex
	dir             string
	trustedKeys     map[string]ed25519.PublicKey
	records         map[string]Record
	defaultRefs     map[string]bool
	manifestVersion string
}

type persistedRecord struct {
	Admission *unsignedAdmission `json:"admission,omitempty"`
	Content   json.RawMessage    `json:"content"`
}

type unsignedAdmission struct {
	AllowUnsigned bool   `json:"allow_unsigned"`
	Digest        string `json:"digest"`
}

func NewStore() *Store {
	return &Store{records: make(map[string]Record), defaultRefs: make(map[string]bool)}
}

func NewStoreWithOptions(opts Options) (*Store, error) {
	store := &Store{dir: strings.TrimSpace(opts.Dir), trustedKeys: opts.TrustedKeys, records: make(map[string]Record), defaultRefs: make(map[string]bool)}
	if store.dir == "" {
		return store, nil
	}
	if err := os.MkdirAll(store.dir, 0o755); err != nil {
		return nil, err
	}
	if err := store.Load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) Load() error {
	if strings.TrimSpace(s.dir) == "" {
		return nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	records := make(map[string]Record)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return err
		}
		raw, allowUnsigned, err := decodePersistedContent(data)
		if err != nil {
			return fmt.Errorf("load content %s: %w", entry.Name(), err)
		}
		env, err := Parse(raw)
		if err != nil {
			return fmt.Errorf("load content %s: %w", entry.Name(), err)
		}
		if allowUnsigned && !strings.EqualFold(persistedDigest(data), signedDigest(env)) {
			return fmt.Errorf("load content %s (%s): unsigned admission digest mismatch", entry.Name(), env.Metadata.ID)
		}
		if err := s.Validate(env, allowUnsigned); err != nil {
			return fmt.Errorf("load content %s (%s): %w", entry.Name(), env.Metadata.ID, err)
		}
		if _, exists := records[env.Metadata.ID]; exists {
			return fmt.Errorf("load content %s: duplicate content ref %s", entry.Name(), env.Metadata.ID)
		}
		record := Record{
			Ref:     env.Metadata.ID,
			Kind:    env.Kind,
			Version: env.Metadata.Version,
			Digest:  signedDigest(env),
			Signed:  strings.TrimSpace(env.Integrity.Signature) != "",
			Status:  "loaded",
			RawJSON: raw,
		}
		if err := validateRecordPayload(record); err != nil {
			return fmt.Errorf("load content %s (%s): %w", entry.Name(), env.Metadata.ID, err)
		}
		records[env.Metadata.ID] = record
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = records
	return nil
}

func validateRecordPayload(record Record) error {
	switch record.Kind {
	case "rulepack":
		if _, err := parseRulePack(record); err != nil {
			return fmt.Errorf("parse rulepack: %w", err)
		}
	case "contextset", "iocpack":
		if _, err := parseValueSet(record); err != nil {
			return fmt.Errorf("parse %s: %w", record.Kind, err)
		}
	}
	return nil
}

func (s *Store) Apply(raw string, allowUnsigned bool, dryRun bool) (Record, error) {
	record, _, err := s.Prepare(raw, allowUnsigned)
	if err != nil {
		return Record{}, err
	}
	if dryRun {
		record.Status = "validated"
		return record, nil
	}
	if err := s.Commit(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Store) Prepare(raw string, allowUnsigned bool) (Record, Snapshot, error) {
	env, err := Parse(raw)
	if err != nil {
		return Record{}, Snapshot{}, err
	}
	if s.IsDefaultRef(env.Metadata.ID) {
		return Record{}, Snapshot{}, fmt.Errorf("default content ref %s is read-only", env.Metadata.ID)
	}
	if err := s.Validate(env, allowUnsigned); err != nil {
		return Record{}, Snapshot{}, err
	}
	raw, env, err = s.resolvePatch(env)
	if err != nil {
		return Record{}, Snapshot{}, err
	}
	record := Record{
		Ref:     env.Metadata.ID,
		Kind:    env.Kind,
		Version: env.Metadata.Version,
		Digest:  signedDigest(env),
		Signed:  strings.TrimSpace(env.Integrity.Signature) != "",
		Status:  "applied",
		RawJSON: raw,
	}
	if err := validateRecordPayload(record); err != nil {
		return Record{}, Snapshot{}, err
	}
	return record, s.SnapshotWith(record), nil
}

func (s *Store) Commit(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]Record)
	}
	previous, existed := s.records[record.Ref]
	s.records[record.Ref] = record
	if err := s.persistLocked(record); err != nil {
		if existed {
			s.records[record.Ref] = previous
		} else {
			delete(s.records, record.Ref)
		}
		return err
	}
	return nil
}

func (s *Store) List(kind string) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Record
	for _, record := range s.records {
		if kind != "" && record.Kind != kind {
			continue
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].Ref < out[j].Ref
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func (s *Store) Get(ref string) (Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[ref]
	return record, ok
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := snapshotFromRecords(s.records)
	snapshot.DefaultManifestVersion = s.manifestVersion
	return snapshot
}

func (s *Store) SnapshotWith(record Record) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make(map[string]Record, len(s.records)+1)
	for ref, current := range s.records {
		records[ref] = current
	}
	if record.Ref != "" {
		records[record.Ref] = record
	}
	snapshot := snapshotFromRecords(records)
	snapshot.DefaultManifestVersion = s.manifestVersion
	return snapshot
}

func snapshotFromRecords(records map[string]Record) Snapshot {
	out := Snapshot{
		RulePacks:   make(map[string]Record),
		ContextSets: make(map[string]ValueSet),
		IOCPacks:    make(map[string]ValueSet),
	}
	for _, record := range records {
		switch record.Kind {
		case "rulepack":
			out.RulePacks[record.Ref] = record
			if rules, err := parseRulePack(record); err == nil {
				out.Rules = append(out.Rules, rules...)
			}
		case "contextset":
			if set, err := parseValueSet(record); err == nil {
				out.ContextSets[record.Ref] = set
			}
		case "iocpack":
			if set, err := parseValueSet(record); err == nil {
				out.IOCPacks[record.Ref] = set
			}
		case "content-bundle":
			// Bundle expansion is intentionally deferred; local tests apply
			// individual packages first so each ref has an addressable record.
		}
	}
	return out
}
