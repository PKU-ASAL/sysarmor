package tetragon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestBackendLiveApplyReplacesGeneratedTracingPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed policy live apply test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appliedPath := filepath.Join(dir, "applied")
	opsPath := filepath.Join(dir, "ops")
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then echo add >> '" + opsPath + "'; cp \"$3\" '" + appliedPath + "'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy delete\" ]; then echo delete >> '" + opsPath + "'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	oldIntent := contract.CollectionIntent{
		Behaviors:    []string{"file.write"},
		FilePrefixes: []string{"/old"},
		ObserveOnly:  true,
	}
	if _, err := backend.Apply(context.Background(), oldIntent); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	backend.mu.Lock()
	backend.policyLoaded = true
	backend.runtimePolicyApplied = true
	backend.mu.Unlock()
	newIntent := contract.CollectionIntent{
		Behaviors:      []string{"network.connect"},
		SocketFamilies: []string{"AF_INET"},
		ObserveOnly:    true,
	}
	if _, err := backend.Apply(context.Background(), newIntent); err != nil {
		t.Fatalf("live Apply() error = %v", err)
	}
	ops, err := os.ReadFile(opsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(ops)) != "delete\nadd" {
		t.Fatalf("ops = %q", string(ops))
	}
	applied, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(applied), "security_socket_connect") || strings.Contains(string(applied), "/old") {
		t.Fatalf("applied policy =\n%s", string(applied))
	}
}

func TestBackendApplyPreparesPolicyWhenManagedSensorStopped(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invokedPath := filepath.Join(dir, "tetra-invoked")
	tetraPath := filepath.Join(dir, "tetra")
	if err := os.WriteFile(tetraPath, []byte("#!/bin/sh\ntouch '"+invokedPath+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{
		TetraPath: tetraPath, TetragonPath: filepath.Join(dir, "tetragon"),
	})
	backend.policyLoaded = true
	backend.runtimePolicyApplied = true
	intent := contract.CollectionIntent{Behaviors: []string{"network.connect"}, ObserveOnly: true}
	result, err := backend.Apply(context.Background(), intent)
	if err != nil || result.State != contract.ApplyStateDeferred {
		t.Fatalf("Apply() result = %+v error = %v, want deferred policy while managed sensor is stopped", result, err)
	}
	if _, err := os.Stat(invokedPath); !os.IsNotExist(err) {
		t.Fatalf("stopped managed sensor invoked tetra: err=%v", err)
	}
	if backend.policyLoaded || backend.runtimePolicyApplied || len(backend.intent.Behaviors) != 1 || backend.intent.Behaviors[0] != "network.connect" {
		t.Fatalf("prepared backend state = loaded=%t runtime=%t intent=%+v", backend.policyLoaded, backend.runtimePolicyApplied, backend.intent)
	}
}

func TestBackendApplyDefersPolicyChangeForManagedSensor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed sensor readiness test requires /bin/sh")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	invokedPath := filepath.Join(dir, "tetra-invoked")
	tetraPath := filepath.Join(dir, "tetra")
	if err := os.WriteFile(tetraPath, []byte("#!/bin/sh\ntouch '"+invokedPath+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{
		TetraPath: tetraPath, TetragonPath: filepath.Join(dir, "tetragon"),
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := backend.sensorSupervisor.Start(ctx, ProcessSpec{
		Name: "starting-tetragon", Path: "/bin/sh", Args: []string{"-c", "sleep 30"},
	}); err != nil {
		t.Fatalf("start sensor process: %v", err)
	}
	defer backend.sensorSupervisor.Stop(context.Background())
	backend.policyLoaded = true
	backend.runtimePolicyApplied = true
	backend.running = true

	intent := contract.CollectionIntent{Behaviors: []string{"network.connect"}, ObserveOnly: true}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer applyCancel()
	result, err := backend.Apply(applyCtx, intent)
	if err != nil || result.State != contract.ApplyStateDeferred {
		t.Fatalf("Apply() result = %+v error = %v, want deferred policy for managed sensor", result, err)
	}
	if _, err := os.Stat(invokedPath); !os.IsNotExist(err) {
		t.Fatalf("managed sensor policy change invoked tetra before resubscribe: err=%v", err)
	}
}

func TestBackendDeletesGeneratedTracingPolicyOnStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed policy cleanup test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(`{"behaviors":["process.exec"],"observe_only":true}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	addedPath := filepath.Join(dir, "added")
	deletedPath := filepath.Join(dir, "deleted")
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then cp \"$3\" '" + addedPath + "'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy delete\" ]; then printf '%s' \"$3\" > '" + deletedPath + "'; exit 0; fi\nprintf '%s\\n' '" + raw + "'\nsleep 30\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	intent := contract.CollectionIntent{
		Behaviors:   []string{"process.exec"},
		ObserveOnly: true,
	}
	if _, err := backend.Apply(context.Background(), intent); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	events, err := backend.Subscribe(ctx, intent)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
	cancel()
	select {
	case _, ok := <-events:
		for ok {
			_, ok = <-events
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for subscription close")
	}
	if _, err := os.Stat(addedPath); err != nil {
		t.Fatalf("generated tracing policy was not applied: %v", err)
	}
	data, err := os.ReadFile(deletedPath)
	if err != nil {
		t.Fatalf("generated tracing policy was not deleted: %v", err)
	}
	if string(data) != runtimeTracingPolicyName {
		t.Fatalf("deleted policy = %q, want %q", string(data), runtimeTracingPolicyName)
	}
}

func TestBackendRejectsUnverifiedGeneratedTracingPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed policy verify test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(`{"behaviors":["network.connect"],"observe_only":true}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'other-policy'; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	intent := contract.CollectionIntent{
		Behaviors:   []string{"network.connect"},
		ObserveOnly: true,
	}
	if _, err := backend.Apply(context.Background(), intent); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := backend.Subscribe(context.Background(), intent); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("Subscribe() error = %v, want not listed", err)
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.PolicyLoaded || !strings.Contains(health.LastError, "not listed") {
		t.Fatalf("health = %+v", health)
	}
}

func TestBackendRestartsManagedSensorProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed sensor restart test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(dir, "count")
	tetragonPath := filepath.Join(dir, "tetragon")
	tetragonScript := "#!/bin/sh\nwhile [ $# -gt 0 ]; do shift; done\nCOUNT='" + countPath + "'\nn=0\nif [ -f \"$COUNT\" ]; then n=$(cat \"$COUNT\"); fi\nn=$((n+1))\nprintf '%s' \"$n\" > \"$COUNT\"\nexit 7\n"
	if err := os.WriteFile(tetragonPath, []byte(tetragonScript), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nsleep 0.2\nprintf '%s\\n' '" + raw + "'\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithOptions(policyPath, "", "test", BundleConfig{TetraPath: tetraPath, TetragonPath: tetragonPath}, ProcessRestartPolicy{
		Enabled:     true,
		MaxRestarts: 3,
		Delay:       10 * time.Millisecond,
	})
	backend.EventTransport = "tetra"
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	for range events {
	}
	waitForBackendHealth(t, backend, func(health contract.Health) bool {
		return health.RestartCount >= 4 && strings.Contains(health.LastExitReason, "exit status 7")
	})
	data, err := os.ReadFile(countPath)
	if err != nil {
		t.Fatalf("ReadFile(count) error = %v", err)
	}
	if string(data) != "3" {
		t.Fatalf("managed sensor restart count file = %q, want 3", string(data))
	}
}

func TestBackendRecoversManagedSensorAndContinuesEvents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed sensor recovery test requires /bin/sh")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(dir, "count")
	tetragonPath := filepath.Join(dir, "tetragon")
	tetragonScript := "#!/bin/sh\nCOUNT='" + countPath + "'\nn=0\nif [ -f \"$COUNT\" ]; then n=$(cat \"$COUNT\"); fi\nn=$((n+1))\nprintf '%s' \"$n\" > \"$COUNT\"\nif [ \"$n\" -eq 1 ]; then exit 7; fi\nsleep 20\n"
	if err := os.WriteFile(tetragonPath, []byte(tetragonScript), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ] || [ \"$1 $2\" = \"tracingpolicy delete\" ]; then exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nprintf '%s\\n' '" + raw + "'\nsleep 20\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithOptions(policyPath, "", "test", BundleConfig{TetraPath: tetraPath, TetragonPath: tetragonPath}, ProcessRestartPolicy{
		Enabled: true, MaxRestarts: 3, Delay: 10 * time.Millisecond,
	})
	backend.EventTransport = "tetra"
	ctx, cancel := context.WithCancel(context.Background())
	events, err := backend.Subscribe(ctx, contract.CollectionIntent{Behaviors: []string{"process.exec"}})
	if err != nil {
		t.Fatal(err)
	}
	waitForBackendHealth(t, backend, func(health contract.Health) bool {
		data, _ := os.ReadFile(countPath)
		return string(data) == "2" && health.Running && health.RestartCount >= 3
	})
	select {
	case event := <-events:
		if event.SensorEvent.GetBehavior() != "process.exec" {
			t.Fatalf("event=%+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event after sensor recovery")
	}
	data, err := os.ReadFile(countPath)
	if err != nil || string(data) != "2" {
		t.Fatalf("sensor starts=%q err=%v", data, err)
	}
	cancel()
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("event stream did not stop after cancellation")
	}
}

func TestBackendRequiresPolicy(t *testing.T) {
	backend := NewBackend(filepath.Join(t.TempDir(), "missing.yaml"), "-", "test")
	if _, err := backend.Subscribe(context.Background(), contract.CollectionIntent{}); err == nil {
		t.Fatal("Subscribe() error = nil")
	}
}

func TestBackendRecordsParseErrors(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	eventPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventPath, []byte("{bad-json}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for closed events")
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.ParseErrors != 1 {
		t.Fatalf("ParseErrors = %d", health.ParseErrors)
	}
}

func waitForBackendHealth(t *testing.T, backend *Backend, done func(contract.Health) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	var last contract.Health
	for time.Now().Before(deadline) {
		health, err := backend.Health(context.Background())
		if err != nil {
			t.Fatalf("Health() error = %v", err)
		}
		last = health
		if done(health) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for backend health, last = %+v", last)
}
