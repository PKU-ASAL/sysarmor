package tetragon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type Backend struct {
	PolicyPath               string
	EventSource              string
	EventTransport           string
	ServerAddress            string
	Version                  string
	Bundle                   BundleConfig
	Restart                  ProcessRestartPolicy
	CgroupRate               string
	PprofAddress             string
	GopsAddress              string
	ProcessCacheSize         int
	DataCacheSize            int
	EventQueueSize           int
	RBQueueSize              string
	ScopeType                string
	ScopeSelector            string
	namespaceSelfContainerID string
	BTFPath                  string
	BPFFSPath                string
	RequireBTF               bool
	RequireBPFFS             bool

	mu                   sync.Mutex
	intent               contract.CollectionIntent
	policyLoaded         bool
	running              bool
	installed            bool
	eventsSeen           uint64
	eventsDropped        uint64
	parseErrors          uint64
	lastEventAt          time.Time
	lastError            string
	runtimePolicyApplied bool

	sensorSupervisor ProcessSupervisor
	eventSupervisor  ProcessSupervisor
}

type ProcessRestartPolicy struct {
	Enabled     bool
	MaxRestarts int
	Delay       time.Duration
}

func NewBackend(policyPath, eventSource, version string) *Backend {
	return NewBackendWithBundle(policyPath, eventSource, version, BundleConfig{})
}

func NewBackendWithBundle(policyPath, eventSource, version string, bundle BundleConfig) *Backend {
	if version == "" {
		version = "unknown"
	}
	return &Backend{PolicyPath: policyPath, EventSource: eventSource, Version: version, Bundle: bundle}
}

func NewBackendWithOptions(policyPath, eventSource, version string, bundle BundleConfig, restart ProcessRestartPolicy) *Backend {
	backend := NewBackendWithBundle(policyPath, eventSource, version, bundle)
	backend.Restart = restart
	return backend
}

func (b *Backend) Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	if b.PolicyPath == "" {
		err := fmt.Errorf("tetragon policy path is required")
		b.setError(err)
		return contract.ApplyResult{}, err
	}
	normalized, err := intent.NormalizeScope()
	if err != nil {
		b.setError(err)
		return contract.ApplyResult{}, err
	}
	normalized, err = resolveNamespaceScope(normalized)
	if err != nil {
		b.setError(err)
		return contract.ApplyResult{}, err
	}
	if err := validateSupportedScope(normalized); err != nil {
		b.setError(err)
		return contract.ApplyResult{}, err
	}
	selfContainerID, err := resolveNamespaceSelfContainerID(normalized)
	if err != nil {
		b.setError(err)
		return contract.ApplyResult{}, err
	}
	if _, err := os.Stat(b.PolicyPath); err != nil {
		b.setError(err)
		return contract.ApplyResult{}, fmt.Errorf("verify tetragon policy: %w", err)
	}
	b.mu.Lock()
	b.namespaceSelfContainerID = selfContainerID
	loaded := b.policyLoaded
	oldIntent := b.intent
	oldRuntimePolicyApplied := b.runtimePolicyApplied
	b.mu.Unlock()
	if loaded && b.canLiveApply() {
		if err := b.liveApplyTracingPolicy(ctx, oldIntent, normalized, oldRuntimePolicyApplied); err != nil {
			b.setError(err)
			return contract.ApplyResult{}, err
		}
		b.mu.Lock()
		b.intent = normalized
		b.policyLoaded = true
		b.runtimePolicyApplied = needsTracingPolicy(normalized)
		b.lastError = ""
		b.mu.Unlock()
		return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
	}
	b.mu.Lock()
	b.intent = normalized
	b.policyLoaded = false
	b.runtimePolicyApplied = false
	b.lastError = ""
	b.mu.Unlock()
	if b.Bundle.TetragonPath != "" {
		return contract.ApplyResult{State: contract.ApplyStateDeferred}, nil
	}
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (b *Backend) canLiveApply() bool {
	if b.Bundle.TetraPath == "" || b.EventSource != "" {
		return false
	}
	return b.Bundle.TetragonPath == ""
}

func (b *Backend) prepareBundle() (BundleVerification, error) {
	if b.Bundle.InstallDir != "" {
		rootDir := filepath.Join(b.Bundle.InstallDir, "tetragon")
		currentDir := filepath.Join(rootDir, "current")
		if !dirExists(currentDir) {
			return BundleVerification{}, fmt.Errorf("tetragon bundle is not staged at %s", currentDir)
		}
		versionDir, err := filepath.EvalSymlinks(currentDir)
		if err != nil {
			return BundleVerification{}, fmt.Errorf("resolve staged tetragon bundle: %w", err)
		}
		rootDir, err = filepath.Abs(rootDir)
		if err != nil {
			return BundleVerification{}, fmt.Errorf("resolve tetragon install directory: %w", err)
		}
		versionDir, err = filepath.Abs(versionDir)
		if err != nil {
			return BundleVerification{}, fmt.Errorf("resolve tetragon version directory: %w", err)
		}
		if filepath.Dir(versionDir) != rootDir || filepath.Base(versionDir) == "current" {
			return BundleVerification{}, fmt.Errorf("staged tetragon bundle points outside install directory: %s", versionDir)
		}
		return VerifyBundle(BundleConfig{
			BundleDir:    versionDir,
			TetraPath:    filepath.Join(versionDir, "bin", "tetra"),
			TetragonPath: filepath.Join(versionDir, "bin", "tetragon"),
		})
	}
	return VerifyBundle(b.Bundle)
}

func (b *Backend) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "tetragon backend is observe-only in v2"), nil
}
