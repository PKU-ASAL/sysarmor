package tetragon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	domainevent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/event"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func (b *Backend) Subscribe(ctx context.Context, intent contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	if err := b.ensureIntent(ctx, intent); err != nil {
		return nil, err
	}
	stopSensor, err := b.startManagedSensor(ctx)
	if err != nil {
		b.setError(err)
		return nil, err
	}
	if b.requiresManagedSensorReady() {
		if err := b.waitManagedSensorReady(ctx); err != nil {
			stopSensor()
			b.setError(err)
			return nil, err
		}
	}
	if err := b.applyPreparedPolicy(ctx); err != nil {
		stopSensor()
		b.setError(err)
		return nil, err
	}
	if b.useGRPCEventSource() {
		return b.subscribeManagedGRPC(ctx, stopSensor)
	}
	source, closeSource, err := b.openEventSource(ctx)
	if err != nil {
		stopSensor()
		b.setError(err)
		return nil, err
	}
	b.mu.Lock()
	b.policyLoaded = true
	b.running = true
	b.lastError = ""
	b.mu.Unlock()

	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		defer b.setRunning(false)
		defer b.cleanupRuntimePolicy()
		defer stopSensor()
		defer closeSource()
		scanner := bufio.NewScanner(source)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			if len(line) == 0 {
				continue
			}
			if dropped, ok := ParseDroppedEvents(line); ok {
				b.incDroppedEvents(dropped)
				continue
			}
			events, ok := ParseLine(line)
			if !ok {
				b.incParseError(fmt.Errorf("unrecognized tetragon event"))
				continue
			}
			rawRef := rawRefForLine(line)
			for _, event := range events {
				if !b.matchesIntentBehavior(event.GetBehavior()) {
					continue
				}
				if !b.matchesScope(event) {
					continue
				}
				if event.RawRef == "" {
					event.RawRef = rawRef
				}
				ev := contract.EventEnvelope{
					SensorEvent: event,
					RawRef:      event.GetRawRef(),
					ReceivedAt:  time.Now().UTC(),
				}
				select {
				case <-ctx.Done():
					return
				case out <- ev:
					b.incEvent(ev.ReceivedAt)
				}
			}
		}
		if err := scanner.Err(); err != nil && !isBenignEventSourceReadError(err) {
			b.setError(err)
		}
	}()
	return out, nil
}

func (b *Backend) matchesIntentBehavior(behavior string) bool {
	b.mu.Lock()
	intent := b.intent
	b.mu.Unlock()
	if len(intent.Behaviors) == 0 {
		return true
	}
	return intentHasBehavior(intent, behavior)
}

func isBenignEventSourceReadError(err error) bool {
	if err == nil {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "file already closed") || strings.Contains(text, "closed pipe")
}

func (b *Backend) Health(context.Context) (contract.Health, error) {
	b.mu.Lock()
	running := b.running
	lastError := b.lastError
	b.mu.Unlock()
	status := b.eventSupervisor.Status()
	sensorStatus := b.sensorSupervisor.Status()
	if status.Running || sensorStatus.Running {
		running = true
	}
	restarts := status.RestartCount + sensorStatus.RestartCount
	lastExit, processError := mergedProcessExit(status, sensorStatus)
	if processError != "" {
		lastError = processError
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return contract.Health{
		Backend:        "tetragon",
		Running:        running,
		Installed:      b.installed,
		Version:        b.Version,
		PolicyLoaded:   b.policyLoaded,
		EventsSeen:     b.eventsSeen,
		EventsDropped:  b.eventsDropped,
		ParseErrors:    b.parseErrors,
		RestartCount:   restarts,
		LastEventAt:    b.lastEventAt,
		LastExitReason: lastExit,
		LastError:      lastError,
	}, nil
}

func mergedProcessExit(statuses ...ProcessStatus) (string, string) {
	for _, status := range statuses {
		if status.LastError != "" {
			return status.LastExit, status.LastError
		}
	}
	for _, status := range statuses {
		if status.LastExit != "" {
			return status.LastExit, ""
		}
	}
	return "", ""
}

func (b *Backend) startManagedSensor(ctx context.Context) (func(), error) {
	if b.Bundle.TetragonPath == "" {
		return func() {}, nil
	}
	_ = os.MkdirAll("/var/run/tetragon", 0o755)
	_ = os.Remove("/var/run/tetragon/tetragon.pid")
	spec := ProcessSpec{
		Name:    "tetragon",
		Path:    b.Bundle.TetragonPath,
		Args:    b.tetragonArgs(b.Bundle.TetragonPath),
		Dir:     bundleRuntimeDir(b.Bundle.TetragonPath),
		LogPath: "/var/log/sysarmor/tetragon.log",
	}
	if b.Restart.Enabled {
		if err := b.sensorSupervisor.StartRestarting(ctx, spec, RestartPolicy{
			MaxRestarts: b.Restart.MaxRestarts,
			Delay:       b.Restart.Delay,
		}); err != nil {
			return nil, err
		}
	} else if err := b.sensorSupervisor.Start(ctx, spec); err != nil {
		return nil, err
	}
	return func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.sensorSupervisor.Stop(stopCtx)
	}, nil
}

func (b *Backend) waitManagedSensorReady(ctx context.Context) error {
	if b.Bundle.TetragonPath == "" || b.Bundle.TetraPath == "" {
		return nil
	}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for {
		cmd := exec.CommandContext(ctx, b.Bundle.TetraPath, "tracingpolicy", "list")
		output, err := cmd.CombinedOutput()
		if err == nil {
			return nil
		}
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			lastErr = fmt.Errorf("wait tetragon ready: %w", err)
		} else {
			lastErr = fmt.Errorf("wait tetragon ready: %w: %s", err, trimmed)
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

func (b *Backend) requiresManagedSensorReady() bool {
	return b.Bundle.BundleDir != "" && b.Bundle.InstallDir != "" && b.Bundle.TetragonPath != ""
}

func tetragonArgs(tetragonPath string) []string {
	args := defaultTetragonArgs()
	if libPath := bundleTetragonLibDir(tetragonPath); libPath != "" {
		args = append(args, "--bpf-lib", libPath)
	}
	return args
}

func (b *Backend) tetragonArgs(tetragonPath string) []string {
	args := tetragonArgs(tetragonPath)
	if b.useGRPCEventSource() {
		args = append(args, "--server-address", firstNonEmpty(b.ServerAddress, defaultTetragonServerAddress))
	}
	if strings.TrimSpace(b.CgroupRate) != "" {
		args = append(args, "--cgroup-rate", strings.TrimSpace(b.CgroupRate))
	}
	if strings.TrimSpace(b.PprofAddress) != "" {
		args = append(args, "--pprof-address", strings.TrimSpace(b.PprofAddress))
	}
	if strings.TrimSpace(b.GopsAddress) != "" {
		args = append(args, "--gops-address", strings.TrimSpace(b.GopsAddress))
	}
	if b.ProcessCacheSize > 0 {
		args = append(args, "--process-cache-size", strconv.Itoa(b.ProcessCacheSize))
	}
	if b.DataCacheSize > 0 {
		args = append(args, "--data-cache-size", strconv.Itoa(b.DataCacheSize))
	}
	if b.EventQueueSize > 0 {
		args = append(args, "--event-queue-size", strconv.Itoa(b.EventQueueSize))
	}
	if strings.TrimSpace(b.RBQueueSize) != "" {
		args = append(args, "--rb-queue-size", strings.TrimSpace(b.RBQueueSize))
	}
	return args
}

func defaultTetragonArgs() []string {
	args := []string{
		"--log-level", "warn",
		"--metrics-server", "",
		"--health-server-address", "",
		"--enable-tracing-policy-crd=false",
		"--enable-process-cred=false",
		"--enable-process-ns=false",
		"--enable-process-environment-variables=false",
		"--enable-ancestors", "",
		"--enable-k8s-api=false",
		"--enable-pod-annotations=false",
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		args = append(args, "--btf", "/sys/kernel/btf/vmlinux")
	}
	return args
}

func tetraGetEventsArgs(intent contract.CollectionIntent) []string {
	args := []string{"getevents", "-o", "json", "--policy-names", runtimeTracingPolicyName}
	eventTypes := tetraEventTypesForIntent(intent)
	if len(eventTypes) > 0 {
		args = append(args, "--event-types", strings.Join(eventTypes, ","))
	}
	return args
}

func tetraEventTypesForIntent(intent contract.CollectionIntent) []string {
	types := map[string]bool{}
	for _, behavior := range intent.Behaviors {
		switch domainevent.NormalizeBehavior(behavior) {
		case domainevent.BehaviorProcessExec,
			domainevent.BehaviorProcessFork,
			domainevent.BehaviorProcessExit,
			domainevent.BehaviorNetworkConnect,
			domainevent.BehaviorFileOpen,
			domainevent.BehaviorFileRead,
			domainevent.BehaviorFileWrite,
			domainevent.BehaviorFileChmod:
			types["PROCESS_KPROBE"] = true
		}
	}
	var out []string
	for _, eventType := range []string{"PROCESS_KPROBE"} {
		if types[eventType] {
			out = append(out, eventType)
		}
	}
	return out
}

func bundleTetragonLibDir(tetragonPath string) string {
	if strings.TrimSpace(tetragonPath) == "" {
		return ""
	}
	root := filepath.Dir(filepath.Dir(tetragonPath))
	candidates := []string{
		filepath.Join(root, "lib", "tetragon", "bpf"),
		filepath.Join(root, "usr", "local", "lib", "tetragon", "bpf"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func (b *Backend) openEventSource(ctx context.Context) (io.Reader, func(), error) {
	switch b.EventSource {
	case "":
		return b.openManagedEventSource(ctx)
	case "-":
		return os.Stdin, func() {}, nil
	default:
		f, err := os.Open(b.EventSource)
		if err != nil {
			return nil, func() {}, err
		}
		return f, func() { _ = f.Close() }, nil
	}
}

func (b *Backend) openManagedEventSource(ctx context.Context) (io.Reader, func(), error) {
	if b.Bundle.TetraPath == "" {
		return nil, func() {}, fmt.Errorf("tetragon tetra_path is required for managed event subscription")
	}
	stdout, err := b.eventSupervisor.StartWithStdout(ctx, ProcessSpec{
		Name: "tetra-getevents",
		Path: b.Bundle.TetraPath,
		Args: tetraGetEventsArgs(b.intent),
		Dir:  bundleRuntimeDir(b.Bundle.TetraPath),
	})
	if err != nil {
		return nil, func() {}, err
	}
	return stdout, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = b.eventSupervisor.Stop(ctx)
		_ = stdout.Close()
	}, nil
}

func (b *Backend) useGRPCEventSource() bool {
	if b.EventSource != "" {
		return false
	}
	transport := strings.TrimSpace(b.EventTransport)
	return transport == "" || transport == "grpc"
}

func bundleRuntimeDir(binaryPath string) string {
	if strings.TrimSpace(binaryPath) == "" {
		return ""
	}
	dir := filepath.Dir(binaryPath)
	if filepath.Base(dir) == "bin" {
		return filepath.Dir(dir)
	}
	return dir
}

func (b *Backend) matchesScope(event *sensorv1.SensorEvent) bool {
	scopeType := strings.TrimSpace(b.ScopeType)
	scopeSelector := strings.TrimSpace(b.ScopeSelector)
	switch scopeType {
	case "":
		return true
	case "host":
		return true
	case "container":
		return containerIDsMatch(event.GetContainerId(), scopeSelector)
	case "cgroup":
		return strings.HasPrefix(event.GetProc().GetCgroup(), scopeSelector)
	case "namespace":
		b.mu.Lock()
		hasNamespaceSelectors := len(b.intent.NamespaceSelectors) > 0
		selfContainerID := b.namespaceSelfContainerID
		b.mu.Unlock()
		if scopeSelector == "self" && hasNamespaceSelectors {
			if selfContainerID == "" {
				return event.GetContainerId() == ""
			}
			return containerIDsMatch(event.GetContainerId(), selfContainerID)
		}
		return strings.HasPrefix(event.GetProc().GetCgroup(), scopeSelector)
	case "pod":
		return strings.HasPrefix(event.GetContainerId(), scopeSelector)
	default:
		return false
	}
}

func (b *Backend) incEvent(at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventsSeen++
	b.lastEventAt = at
}

func (b *Backend) incParseError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.parseErrors++
	b.lastError = err.Error()
}

func (b *Backend) incDroppedEvents(count uint64) {
	if count == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.eventsDropped += count
	b.lastError = fmt.Sprintf("tetragon dropped events: %d", b.eventsDropped)
}

func (b *Backend) setError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.lastError = err.Error()
	}
}

func (b *Backend) setRunning(running bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.running = running
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func rawRefForLine(line []byte) string {
	sum := sha256.Sum256(line)
	return "tetragon:" + hex.EncodeToString(sum[:8])
}
