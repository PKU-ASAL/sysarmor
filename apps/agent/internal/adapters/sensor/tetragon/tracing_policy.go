package tetragon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

const runtimeTracingPolicyName = "sysarmor-runtime-collection"

func (b *Backend) ensureIntent(ctx context.Context, intent contract.CollectionIntent) error {
	explicitScope := strings.TrimSpace(intent.ScopeType) != "" || strings.TrimSpace(intent.ScopeSelector) != ""
	normalized, err := intent.NormalizeScope()
	if err != nil {
		return err
	}
	normalized, err = resolveNamespaceScope(normalized)
	if err != nil {
		return err
	}
	if err := validateSupportedScope(normalized); err != nil {
		return err
	}
	if explicitScope {
		b.ScopeType = normalized.ScopeType
		b.ScopeSelector = normalized.ScopeSelector
	}
	b.mu.Lock()
	loaded := b.policyLoaded
	hasIntent := len(b.intent.Behaviors) > 0 || b.intent.ObserveOnly || len(b.intent.FilePrefixes) > 0 || len(b.intent.SocketFamilies) > 0
	b.mu.Unlock()
	if loaded || hasIntent {
		return nil
	}
	_, err = b.Apply(ctx, normalized)
	return err
}

func validateSupportedScope(intent contract.CollectionIntent) error {
	switch intent.ScopeType {
	case "", "host", "container", "cgroup", "namespace", "pod":
		return nil
	default:
		return fmt.Errorf("tetragon backend scope %q is not supported", intent.ScopeType)
	}
}

func resolveNamespaceScope(intent contract.CollectionIntent) (contract.CollectionIntent, error) {
	if intent.ScopeType != "namespace" || intent.ScopeSelector != "self" || len(intent.NamespaceSelectors) > 0 {
		return intent, nil
	}
	selectors, err := selfNamespaceSelectors()
	if err != nil {
		return contract.CollectionIntent{}, err
	}
	intent.NamespaceSelectors = selectors
	return intent, nil
}

func selfNamespaceSelectors() ([]contract.NamespaceSelector, error) {
	namespaces := []struct {
		name string
		tp   string
	}{
		{name: "pid", tp: "Pid"},
		{name: "mnt", tp: "Mnt"},
	}
	out := make([]contract.NamespaceSelector, 0, len(namespaces))
	for _, ns := range namespaces {
		link, err := os.Readlink(filepath.Join("/proc/self/ns", ns.name))
		if err != nil {
			return nil, fmt.Errorf("resolve namespace scope %s: %w", ns.name, err)
		}
		inode, ok := namespaceInode(link)
		if !ok {
			return nil, fmt.Errorf("resolve namespace scope %s: unexpected link %q", ns.name, link)
		}
		out = append(out, contract.NamespaceSelector{Namespace: ns.tp, Values: []string{inode}})
	}
	return out, nil
}

func namespaceInode(link string) (string, bool) {
	start := strings.Index(link, "[")
	end := strings.Index(link, "]")
	if start < 0 || end <= start+1 {
		return "", false
	}
	inode := link[start+1 : end]
	if _, err := strconv.ParseUint(inode, 10, 64); err != nil {
		return "", false
	}
	return inode, true
}

func (b *Backend) applyPreparedPolicy(ctx context.Context) error {
	b.mu.Lock()
	if b.policyLoaded {
		b.mu.Unlock()
		return nil
	}
	intent := b.intent
	b.mu.Unlock()

	if b.Bundle.TetraPath != "" && b.EventSource == "" && needsTracingPolicy(intent) {
		path, err := b.renderTracingPolicy(intent)
		if err != nil {
			return err
		}
		if err := b.applyTracingPolicy(ctx, path); err != nil {
			return err
		}
	}
	b.mu.Lock()
	b.policyLoaded = true
	if b.Bundle.TetraPath != "" && b.EventSource == "" && needsTracingPolicy(intent) {
		b.runtimePolicyApplied = true
	}
	b.lastError = ""
	b.mu.Unlock()
	return nil
}

func (b *Backend) cleanupRuntimePolicy() {
	b.mu.Lock()
	shouldCleanup := b.runtimePolicyApplied
	b.runtimePolicyApplied = false
	b.mu.Unlock()
	if !shouldCleanup || b.Bundle.TetraPath == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.Bundle.TetraPath, "tracingpolicy", "delete", runtimeTracingPolicyName)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	trimmed := strings.TrimSpace(string(output))
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "not found") || strings.Contains(lower, "notfound") || strings.Contains(lower, "not exist") {
		return
	}
	if trimmed == "" {
		b.setError(fmt.Errorf("delete tetragon tracing policy %s: %w", runtimeTracingPolicyName, err))
		return
	}
	b.setError(fmt.Errorf("delete tetragon tracing policy %s: %w: %s", runtimeTracingPolicyName, err, trimmed))
}

func needsTracingPolicy(intent contract.CollectionIntent) bool {
	for _, behavior := range intent.Behaviors {
		switch domainevent.NormalizeBehavior(behavior) {
		case domainevent.BehaviorNetworkConnect, domainevent.BehaviorFileOpen, domainevent.BehaviorFileRead, domainevent.BehaviorFileWrite, domainevent.BehaviorFileChmod:
			return true
		}
	}
	return false
}

func (b *Backend) renderTracingPolicy(intent contract.CollectionIntent) (string, error) {
	return b.writeTracingPolicy(intent, "sysarmor-runtime-tracingpolicy.yaml")
}

func (b *Backend) writeTracingPolicy(intent contract.CollectionIntent, name string) (string, error) {
	dir := filepath.Dir(b.PolicyPath)
	if dir == "." || dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, name)
	data := buildTracingPolicy(intent)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write tetragon tracing policy: %w", err)
	}
	return path, nil
}

func (b *Backend) liveApplyTracingPolicy(ctx context.Context, oldIntent, newIntent contract.CollectionIntent, oldRuntimePolicyApplied bool) error {
	oldNeeds := oldRuntimePolicyApplied && needsTracingPolicy(oldIntent)
	newNeeds := needsTracingPolicy(newIntent)
	if !oldNeeds && !newNeeds {
		return nil
	}
	var oldPath string
	var err error
	if oldNeeds {
		oldPath, err = b.writeTracingPolicy(oldIntent, "sysarmor-runtime-tracingpolicy-rollback.yaml")
		if err != nil {
			return err
		}
		if err := b.deleteTracingPolicy(ctx); err != nil {
			return err
		}
	}
	if !newNeeds {
		return nil
	}
	newPath, err := b.renderTracingPolicy(newIntent)
	if err != nil {
		return err
	}
	if err := b.applyTracingPolicy(ctx, newPath); err != nil {
		if oldNeeds && oldPath != "" {
			_ = b.applyTracingPolicy(context.Background(), oldPath)
		}
		return err
	}
	return nil
}

func (b *Backend) deleteTracingPolicy(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, b.Bundle.TetraPath, "tracingpolicy", "delete", runtimeTracingPolicyName)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(output))
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "not found") || strings.Contains(lower, "notfound") || strings.Contains(lower, "not exist") {
		return nil
	}
	if trimmed == "" {
		return fmt.Errorf("delete tetragon tracing policy %s: %w", runtimeTracingPolicyName, err)
	}
	return fmt.Errorf("delete tetragon tracing policy %s: %w: %s", runtimeTracingPolicyName, err, trimmed)
}

func (b *Backend) applyTracingPolicy(ctx context.Context, path string) error {
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for {
		cmd := exec.CommandContext(ctx, b.Bundle.TetraPath, "tracingpolicy", "add", path)
		output, err := cmd.CombinedOutput()
		if err == nil {
			return b.verifyTracingPolicy(ctx, runtimeTracingPolicyName)
		}
		trimmed := strings.TrimSpace(string(output))
		if strings.Contains(strings.ToLower(trimmed), "already exists") {
			return b.verifyTracingPolicy(ctx, runtimeTracingPolicyName)
		}
		if trimmed == "" {
			lastErr = fmt.Errorf("apply tetragon tracing policy: %w", err)
		} else {
			lastErr = fmt.Errorf("apply tetragon tracing policy: %w: %s", err, trimmed)
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (b *Backend) verifyTracingPolicy(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, b.Bundle.TetraPath, "tracingpolicy", "list")
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if err != nil {
		if trimmed == "" {
			return fmt.Errorf("verify tetragon tracing policy %s: %w", name, err)
		}
		return fmt.Errorf("verify tetragon tracing policy %s: %w: %s", name, err, trimmed)
	}
	if !strings.Contains(trimmed, name) {
		return fmt.Errorf("verify tetragon tracing policy %s: not listed", name)
	}
	return nil
}
