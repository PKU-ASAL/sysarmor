package tetragon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (b *Backend) Capability(context.Context) (contract.Capability, error) {
	if b.Bundle.BundleDir != "" {
		verified, err := b.prepareBundle()
		if err != nil {
			b.setError(err)
			return contract.Capability{}, err
		}
		b.mu.Lock()
		b.installed = true
		b.Bundle.TetraPath = verified.TetraPath
		b.Bundle.TetragonPath = verified.TetragonPath
		b.lastError = ""
		if b.Version == "unknown" {
			b.Version = verified.Version
		}
		b.mu.Unlock()
	} else if b.EventSource != "" {
		b.mu.Lock()
		b.installed = true
		b.mu.Unlock()
	} else if b.Bundle.TetraPath != "" || b.Bundle.TetragonPath != "" {
		b.mu.Lock()
		b.installed = true
		b.mu.Unlock()
	}
	kernelRelease, btfAvailable, bpffsAvailable, err := b.probeHostCapabilities()
	if err != nil {
		b.setError(err)
		return contract.Capability{}, err
	}
	if err := b.verifyConfiguredExecutables(); err != nil {
		b.setError(err)
		return contract.Capability{}, err
	}
	return contract.Capability{
		Backend:         "tetragon",
		Version:         b.Version,
		SupportsExec:    true,
		SupportsConnect: true,
		SupportsFile:    true,
		SupportsHealth:  true,
		KernelRelease:   kernelRelease,
		BTFAvailable:    btfAvailable,
		BPFFSAvailable:  bpffsAvailable,
		Collection:      CollectionCapabilities(),
	}, nil
}

func CollectionCapabilities() []contract.CollectionBehaviorCapability {
	commonProcess := []string{"event.id", "event.behavior", "lineage_id", "process.stable_id", "process.binary", "process.argv", "process.uid", "process.pid", "parent.stable_id", "scope.type", "scope.selector", "container.id", "cgroup"}
	agentSideScope := []string{"scope.container", "scope.cgroup", "scope.pod"}
	with := func(base []string, fields ...string) []string {
		out := append([]string(nil), base...)
		out = append(out, fields...)
		return out
	}
	pushdown := func(selectors ...string) []string {
		return append([]string{"scope.namespace"}, selectors...)
	}
	return []contract.CollectionBehaviorCapability{
		{
			Behavior:           domainevent.BehaviorProcessExec,
			SensorMapping:      "tetragon:process_exec",
			Fields:             commonProcess,
			PushdownSelectors:  pushdown("process.binary_prefix"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorProcessFork,
			SensorMapping:      "tetragon:process_exec.clone",
			Fields:             commonProcess,
			PushdownSelectors:  pushdown("process.binary_prefix"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorProcessExit,
			SensorMapping:      "tetragon:process_exit",
			Fields:             commonProcess,
			PushdownSelectors:  pushdown(),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorNetworkConnect,
			SensorMapping:      "tetragon:kprobe/security_socket_connect",
			Fields:             with(commonProcess, "socket", "socket.addr", "socket.port", "object.socket_addr"),
			PushdownSelectors:  pushdown("process.binary_prefix", "socket.family", "socket.addr", "socket.port"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorFileOpen,
			SensorMapping:      "tetragon:kprobe/security_file_permission",
			Fields:             with(commonProcess, "file.path", "object.file_path"),
			PushdownSelectors:  pushdown("process.binary_prefix", "file.path.prefix"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorFileRead,
			SensorMapping:      "tetragon:kprobe/security_file_permission",
			Fields:             with(commonProcess, "file.path", "object.file_path"),
			PushdownSelectors:  pushdown("process.binary_prefix", "file.path.prefix", "file.access"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorFileWrite,
			SensorMapping:      "tetragon:process_exec.inferred_write/security_file_permission",
			Fields:             with(commonProcess, "file.path", "object.file_path"),
			PushdownSelectors:  pushdown("process.binary_prefix", "file.path.prefix", "file.access"),
			AgentSideSelectors: agentSideScope,
		},
		{
			Behavior:           domainevent.BehaviorFileChmod,
			SensorMapping:      "tetragon:process_exec.inferred_chmod",
			Fields:             with(commonProcess, "file.path", "object.file_path"),
			PushdownSelectors:  pushdown("process.binary_prefix", "file.path.prefix", "file.access"),
			AgentSideSelectors: agentSideScope,
		},
	}
}

func CompileReport(intent contract.CollectionIntent) contract.CollectionCompileReport {
	report := contract.CollectionCompileReport{
		Status:  "ok",
		Backend: "tetragon",
	}
	if needsTracingPolicy(intent) {
		sum := sha256.Sum256(buildTracingPolicy(intent))
		report.GeneratedPolicyHash = hex.EncodeToString(sum[:])
	}
	for _, behavior := range intent.Behaviors {
		behavior = domainevent.NormalizeBehavior(behavior)
		if behavior == "" {
			continue
		}
		report.BehaviorMappings = append(report.BehaviorMappings, contract.CollectionBehaviorMap{
			Behavior: behavior,
			Backend:  "tetragon",
			Hook:     hookForBehavior(behavior),
		})
		filter := behaviorFilter(intent, behavior)
		report.PushedDownSelectors = append(report.PushedDownSelectors, pushedDownSelectorsForFilter(filter)...)
		report.AgentSideSelectors = append(report.AgentSideSelectors, agentSideSelectorsForFilter(filter)...)
		for _, scopeReport := range scopeSelectorReports(intent, behavior) {
			if scopeReport.Status == "pushed_down" {
				report.PushedDownSelectors = append(report.PushedDownSelectors, scopeReport)
				continue
			}
			report.AgentSideSelectors = append(report.AgentSideSelectors, scopeReport)
		}
		report.UnsupportedSelectors = append(report.UnsupportedSelectors, unsupportedSelectorsForFilter(filter)...)
		if !hasPushdownSelectors(intent, behavior, filter) && !intentHasMandatoryBehavior(intent, behavior) {
			report.Warnings = append(report.Warnings, fmt.Sprintf("behavior %s has no pushdown selectors; kernel BPF filter will pass all events of this type, resulting in high event volume", behavior))
		}
	}
	if len(report.AgentSideSelectors) > 0 {
		report.Warnings = append(report.Warnings, "some selectors are enforced agent-side after Tetragon emission; behavior is correct but event volume can be higher")
	}
	if len(report.UnsupportedSelectors) > 0 {
		report.Status = "unsupported"
		report.Warnings = append(report.Warnings, "collection policy contains selectors that are not compiled to Tetragon or enforced agent-side")
	}
	return report
}

func hookForBehavior(behavior string) string {
	switch behavior {
	case domainevent.BehaviorProcessExec, domainevent.BehaviorProcessFork:
		return "process_exec"
	case domainevent.BehaviorProcessExit:
		return "process_exit"
	case domainevent.BehaviorNetworkConnect:
		return "security_socket_connect"
	case domainevent.BehaviorFileOpen, domainevent.BehaviorFileRead, domainevent.BehaviorFileWrite, domainevent.BehaviorFileChmod:
		return "security_file_permission"
	default:
		return ""
	}
}

func hasPushdownSelectors(intent contract.CollectionIntent, behavior string, filter contract.CollectionBehaviorFilter) bool {
	if hasNamespacePushdown(intent) {
		return true
	}
	switch domainevent.NormalizeBehavior(behavior) {
	case domainevent.BehaviorProcessExec, domainevent.BehaviorProcessFork:
		return len(filter.BinaryPrefixes) > 0
	case domainevent.BehaviorNetworkConnect:
		return len(filter.BinaryPrefixes) > 0 || len(filter.SocketAddrs) > 0 || len(filter.SocketPorts) > 0
	case domainevent.BehaviorFileOpen, domainevent.BehaviorFileRead, domainevent.BehaviorFileWrite, domainevent.BehaviorFileChmod:
		return len(filter.BinaryPrefixes) > 0 || len(filter.FilePrefixes) > 0
	default:
		return true
	}
}

func pushedDownSelectorsForFilter(filter contract.CollectionBehaviorFilter) []contract.CollectionSelectorReport {
	var out []contract.CollectionSelectorReport
	behavior := domainevent.NormalizeBehavior(filter.Behavior)
	add := func(selector, mapping string) {
		out = append(out, contract.CollectionSelectorReport{Behavior: behavior, Selector: selector, Status: "pushed_down", Location: "tetragon", Mapping: mapping})
	}
	switch behavior {
	case domainevent.BehaviorProcessExec, domainevent.BehaviorProcessFork:
		if len(filter.BinaryPrefixes) > 0 {
			add("process.binary_prefix", "allow_list.binary_regex")
		}
	case domainevent.BehaviorNetworkConnect:
		if len(filter.BinaryPrefixes) > 0 {
			add("process.binary_prefix", "selectors.matchBinaries[operator=Prefix]")
		}
		if len(filter.SocketFamilies) > 0 {
			add("socket.family", "selectors.matchArgs[index=1,operator=Family]")
		}
	case domainevent.BehaviorFileOpen, domainevent.BehaviorFileRead, domainevent.BehaviorFileWrite, domainevent.BehaviorFileChmod:
		if len(filter.BinaryPrefixes) > 0 {
			add("process.binary_prefix", "selectors.matchBinaries[operator=Prefix]")
		}
		if len(filter.FilePrefixes) > 0 {
			add("file.path.prefix", "selectors.matchArgs[index=0,operator=Prefix]")
		}
		switch behavior {
		case domainevent.BehaviorFileRead:
			add("file.access", "selectors.matchArgs[index=1,operator=Equal,value=4/MAY_READ]")
		case domainevent.BehaviorFileWrite, domainevent.BehaviorFileChmod:
			add("file.access", "selectors.matchArgs[index=1,operator=Equal,value=2/MAY_WRITE]")
		}
	}
	return out
}

func scopeSelectorReports(intent contract.CollectionIntent, behavior string) []contract.CollectionSelectorReport {
	if intent.ScopeType == "" || intent.ScopeType == "host" {
		return nil
	}
	if hasNamespacePushdown(intent) && !isNativeLifecycleBehavior(behavior) {
		return []contract.CollectionSelectorReport{{
			Behavior: behavior,
			Selector: "scope.namespace",
			Status:   "pushed_down",
			Location: "tetragon",
			Mapping:  "selectors.matchNamespaces",
		}}
	}
	return []contract.CollectionSelectorReport{{
		Behavior: behavior,
		Selector: "scope." + intent.ScopeType,
		Status:   "agent_side",
		Location: "agent",
		Reason:   "runtime scope is enforced after Tetragon emission; selector is correct but may collect extra events until backend pushdown is implemented",
	}}
}

func isNativeLifecycleBehavior(behavior string) bool {
	switch domainevent.NormalizeBehavior(behavior) {
	case domainevent.BehaviorProcessExec, domainevent.BehaviorProcessExit, domainevent.BehaviorProcessFork:
		return true
	default:
		return false
	}
}

func hasNamespacePushdown(intent contract.CollectionIntent) bool {
	return intent.ScopeType == "namespace" && (intent.ScopeSelector == "self" || len(intent.NamespaceSelectors) > 0)
}

func agentSideSelectorsForFilter(filter contract.CollectionBehaviorFilter) []contract.CollectionSelectorReport {
	behavior := domainevent.NormalizeBehavior(filter.Behavior)
	if behavior != domainevent.BehaviorNetworkConnect {
		return nil
	}
	var out []contract.CollectionSelectorReport
	add := func(selector, reason string) {
		out = append(out, contract.CollectionSelectorReport{
			Behavior: behavior,
			Selector: selector,
			Status:   "agent_side",
			Location: "agent",
			Reason:   reason,
		})
	}
	if len(filter.SocketAddrs) > 0 {
		add("socket.addr", "destination address IOC is enforced after Tetragon emission until sockaddr destination pushdown is verified")
	}
	if len(filter.SocketPorts) > 0 {
		add("socket.port", "destination port IOC is enforced after Tetragon emission until sockaddr destination pushdown is verified")
	}
	return out
}

func unsupportedSelectorsForFilter(filter contract.CollectionBehaviorFilter) []contract.CollectionSelectorReport {
	return nil
}

func (b *Backend) probeHostCapabilities() (string, bool, bool, error) {
	kernelRelease := runtime.GOOS
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernelRelease = strings.TrimSpace(string(data))
	}
	btfPath := firstNonEmpty(b.BTFPath, "/sys/kernel/btf/vmlinux")
	btfAvailable := fileExists(btfPath)
	bpffsPath := firstNonEmpty(b.BPFFSPath, "/sys/fs/bpf")
	bpffsAvailable := dirExists(bpffsPath)
	if b.RequireBTF && !btfAvailable {
		return kernelRelease, false, bpffsAvailable, fmt.Errorf("btf unavailable at %s", btfPath)
	}
	if b.RequireBPFFS && !bpffsAvailable {
		return kernelRelease, btfAvailable, false, fmt.Errorf("bpffs unavailable at %s", bpffsPath)
	}
	return kernelRelease, btfAvailable, bpffsAvailable, nil
}

func (b *Backend) verifyConfiguredExecutables() error {
	for name, path := range map[string]string{
		"tetra":    b.Bundle.TetraPath,
		"tetragon": b.Bundle.TetragonPath,
	} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("verify %s executable %s: %w", name, path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("verify %s executable %s: is a directory", name, path)
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("verify %s executable %s: not executable", name, path)
		}
	}
	return nil
}
