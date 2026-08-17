package tetragon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tetragonpb "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestEventsFromGRPCResponseProcessKprobe(t *testing.T) {
	resp := &tetragonpb.GetEventsResponse{
		NodeName: "node-a",
		Event: &tetragonpb.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragonpb.ProcessKprobe{
				PolicyName:   runtimeTracingPolicyName,
				FunctionName: "security_socket_connect",
				Process: &tetragonpb.Process{
					Pid:       wrapperspb.UInt32(100),
					Uid:       wrapperspb.UInt32(0),
					Binary:    "/usr/bin/curl",
					Arguments: "-s https://example.test",
				},
				Args: []*tetragonpb.KprobeArgument{{
					Arg: &tetragonpb.KprobeArgument_SockArg{
						SockArg: &tetragonpb.KprobeSock{
							Daddr: "203.0.113.10",
							Dport: 443,
						},
					},
				}},
			},
		},
	}

	events, ok := eventsFromGRPCResponse(resp)
	if !ok || len(events) != 1 {
		t.Fatalf("eventsFromGRPCResponse() = %d,%v, want one event", len(events), ok)
	}
	got := events[0]
	if got.GetBehavior() != "network.connect" {
		t.Fatalf("behavior = %q, want network.connect", got.GetBehavior())
	}
	if got.GetObject().GetDst() != "203.0.113.10:443" {
		t.Fatalf("object = %+v", got.GetObject())
	}
	if got.GetProc().GetBinary() != "/usr/bin/curl" {
		t.Fatalf("proc = %+v", got.GetProc())
	}
}

func TestBenignEventSourceReadErrorIgnored(t *testing.T) {
	if !isBenignEventSourceReadError(ioEOFError("read |0: file already closed")) {
		t.Fatal("expected file already closed to be benign")
	}
	if !isBenignEventSourceReadError(ioEOFError("read |0: closed pipe")) {
		t.Fatal("expected closed pipe to be benign")
	}
	if isBenignEventSourceReadError(ioEOFError("unexpected EOF")) {
		t.Fatal("unexpected EOF should not be benign")
	}
}

type ioEOFError string

func (e ioEOFError) Error() string { return string(e) }

func TestBackendAppliesGeneratedTracingPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed policy apply test requires /bin/sh")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(`{"behaviors":["process.exec","network.connect","file.open"],"observe_only":true}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	raw := `{"process_exec":{"process":{"pid":100,"uid":0,"binary":"/bin/bash","arguments":"-c id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"}},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	appliedPath := filepath.Join(dir, "applied")
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then cp \"$3\" '" + appliedPath + "'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nprintf '%s\\n' '" + raw + "'\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	intent := contract.CollectionIntent{
		Behaviors:   []string{"process.exec", "network.connect", "file.open"},
		ObserveOnly: true,
	}
	if _, err := backend.Apply(context.Background(), intent); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	events, err := backend.Subscribe(context.Background(), intent)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	for range events {
	}
	data, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatalf("generated tracing policy was not applied: %v", err)
	}
	for _, want := range []string{"kind: TracingPolicy", "security_socket_connect", "security_file_permission"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("generated policy missing %q:\n%s", want, string(data))
		}
	}
	health, err := backend.Health(context.Background())
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.PolicyLoaded {
		t.Fatalf("health = %+v", health)
	}
}

func TestBackendAppliesNamespaceSelfTracingPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed policy apply test requires /bin/sh and procfs namespaces")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is unavailable")
	}
	selectors, err := selfNamespaceSelectors()
	if err != nil {
		t.Skipf("namespace selectors unavailable: %v", err)
	}
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "collection.yaml")
	if err := os.WriteFile(policyPath, []byte(`{"behaviors":["process.exec"],"observe_only":true}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	appliedPath := filepath.Join(dir, "applied.yaml")
	tetraPath := filepath.Join(dir, "tetra")
	raw := `{"process_kprobe":{"process":{"pid":100,"uid":0,"binary":"/bin/busybox","arguments":"id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"},"function_name":"security_bprm_creds_from_file","args":[{"file_arg":{"path":"/bin/busybox"}}],"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then cp \"$3\" '" + appliedPath + "'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nprintf '%s\\n' '" + raw + "'\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	intent := contract.CollectionIntent{
		Behaviors:     []string{"process.exec"},
		ScopeType:     "namespace",
		ScopeSelector: "self",
		ObserveOnly:   true,
	}
	if _, err := backend.Apply(context.Background(), intent); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	events, err := backend.Subscribe(context.Background(), intent)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	for range events {
	}
	data, err := os.ReadFile(appliedPath)
	if err != nil {
		t.Fatalf("generated tracing policy was not applied: %v", err)
	}
	text := string(data)
	for _, want := range []string{"matchNamespaces:", "namespace: Pid", "namespace: Mnt"} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated policy missing %q:\n%s", want, text)
		}
	}
	for _, selector := range selectors {
		if len(selector.Values) == 0 || !strings.Contains(text, selector.Values[0]) {
			t.Fatalf("generated policy missing selector %+v:\n%s", selector, text)
		}
	}
}

func TestBackendManagedSubscribeUsesPolicyScopedGetEvents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed subscribe test requires /bin/sh")
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
	argsPath := filepath.Join(dir, "getevents.args")
	raw := `{"process_kprobe":{"process":{"pid":100,"uid":0,"binary":"/bin/busybox","arguments":"id","start_time":"2026-06-14T10:00:00Z"},"parent":{"pid":99,"binary":"/sbin/init","start_time":"2026-06-14T09:59:59Z"},"function_name":"security_bprm_creds_from_file","args":[{"file_arg":{"path":"/bin/busybox"}}],"policy_name":"sysarmor-runtime-collection"},"node_name":"node-a","time":"2026-06-14T10:00:00Z"}`
	tetraPath := filepath.Join(dir, "tetra")
	tetraScript := "#!/bin/sh\nif [ \"$1 $2\" = \"tracingpolicy add\" ]; then exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy list\" ]; then printf '%s\\n' 'sysarmor-runtime-collection'; exit 0; fi\nif [ \"$1 $2\" = \"tracingpolicy delete\" ]; then exit 0; fi\nprintf '%s\\n' \"$*\" > '" + argsPath + "'\nprintf '%s\\n' '" + raw + "'\n"
	if err := os.WriteFile(tetraPath, []byte(tetraScript), 0o755); err != nil {
		t.Fatal(err)
	}
	backend := NewBackendWithBundle(policyPath, "", "test", BundleConfig{TetraPath: tetraPath})
	backend.EventTransport = "tetra"
	intent := contract.CollectionIntent{
		Behaviors:   []string{"process.exec"},
		ObserveOnly: true,
	}
	events, err := backend.Subscribe(context.Background(), intent)
	if err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	var got []string
	for ev := range events {
		got = append(got, ev.SensorEvent.GetBehavior())
	}
	if len(got) != 1 || got[0] != "process.exec" {
		t.Fatalf("behaviors = %v, want process.exec", got)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	joined := string(args)
	for _, want := range []string{"getevents -o json", "--policy-names sysarmor-runtime-collection", "--event-types PROCESS_KPROBE"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tetra args = %q, missing %q", joined, want)
		}
	}
}

func TestBuildTracingPolicyUsesCollectionFilters(t *testing.T) {
	data := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors: []string{"process.exec", "network.connect", "file.write"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{
			{Behavior: "process.exec", BinaryPrefixes: []string{"/var/lib/app/plugins"}},
			{Behavior: "network.connect", BinaryPrefixes: []string{"/usr/bin", "/opt/app/bin"}, SocketFamilies: []string{"AF_INET"}, SocketAddrs: []string{"10.66.0.99"}, SocketPorts: []string{"443", "8080"}},
			{Behavior: "file.write", BinaryPrefixes: []string{"/usr/bin"}, FilePrefixes: []string{"/dev/shm", "/var/lib/app/plugins"}},
		},
	}))
	for _, want := range []string{"security_bprm_creds_from_file", `"Prefix"`, `"security_socket_connect"`, "matchBinaries", `"/usr/bin"`, `"/opt/app/bin"`, `"AF_INET"`, `"security_file_permission"`, `"/dev/shm"`, `"/var/lib/app/plugins"`, `"Equal"`, `"2"`} {
		if !strings.Contains(data, want) {
			t.Fatalf("generated policy missing %q:\n%s", want, data)
		}
	}
	for _, unwanted := range []string{`"SAddr"`, `"SPort"`} {
		if strings.Contains(data, unwanted) {
			t.Fatalf("generated policy should not push down destination IOC selector %q until verified:\n%s", unwanted, data)
		}
	}
	if strings.Contains(data, "AF_INET6") {
		t.Fatalf("generated policy should honor explicit socket families:\n%s", data)
	}
}

func TestBuildTracingPolicyMandatoryBaselineIgnoresNarrowSelectors(t *testing.T) {
	data := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors:          []string{"process.exec", "file.write", "network.connect"},
		MandatoryBehaviors: []string{"process.exec", "file.write", "network.connect"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{{
			Behavior: "network.connect", BinaryPrefixes: []string{"/tmp/"}, SocketPorts: []string{"443"},
			FilePrefixes: []string{"/dev/shm/"},
		}},
	}))
	if strings.Contains(data, `"/tmp/"`) || strings.Contains(data, `"/dev/shm/"`) {
		t.Fatalf("mandatory baseline retained user selectors:\n%s", data)
	}
	if !strings.Contains(data, `- "/"`) {
		t.Fatalf("mandatory file baseline did not widen file selector:\n%s", data)
	}
}

func TestBuildTracingPolicyExcludesRecursiveFileWriteSinks(t *testing.T) {
	data := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors:          []string{"file.write"},
		MandatoryBehaviors: []string{"file.write"},
		FileWriteExcludes:  []string{"/var/log/syslog", "/var/lib/sysarmor", "/run/sysarmor"},
	}))

	if !strings.Contains(data, `operator: "NotPrefix"`) {
		t.Fatalf("mandatory file.write exclusion operator missing:\n%s", data)
	}
	for _, prefix := range []string{"/var/log/syslog", "/var/lib/sysarmor", "/run/sysarmor"} {
		if !strings.Contains(data, fmt.Sprintf("%q", prefix)) {
			t.Fatalf("mandatory file.write exclusion %q missing:\n%s", prefix, data)
		}
	}
}

func TestBuildTracingPolicyPushesNamespaceScope(t *testing.T) {
	data := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors: []string{"process.exec", "network.connect", "file.write"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{
			{Behavior: "process.exec", BinaryPrefixes: []string{"/usr/bin"}},
			{Behavior: "network.connect", SocketFamilies: []string{"AF_INET"}},
			{Behavior: "file.write", FilePrefixes: []string{"/dev/shm"}},
		},
		NamespaceSelectors: []contract.NamespaceSelector{
			{Namespace: "Pid", Values: []string{"4026533001"}},
			{Namespace: "Mnt", Values: []string{"4026533002"}},
		},
	}))
	for _, want := range []string{"matchNamespaces:", "namespace: Pid", "namespace: Mnt", `"4026533001"`, `"4026533002"`} {
		if !strings.Contains(data, want) {
			t.Fatalf("generated policy missing %q:\n%s", want, data)
		}
	}
	if strings.Count(data, "matchNamespaces:") != 3 {
		t.Fatalf("generated policy should attach namespace selectors to each kprobe selector:\n%s", data)
	}
}

func TestBuildTracingPolicySeparatesReadAndWriteFileAccess(t *testing.T) {
	data := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors: []string{"file.read", "file.write"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{
			{Behavior: "file.read", FilePrefixes: []string{"/etc/passwd"}},
			{Behavior: "file.write", FilePrefixes: []string{"/dev/shm"}},
		},
	}))
	if strings.Count(data, "operator: \"Equal\"") != 2 {
		t.Fatalf("generated policy should have separate read/write access selectors:\n%s", data)
	}
	if strings.Contains(data, "\t") {
		t.Fatalf("generated policy contains tabs:\n%s", data)
	}
	for _, want := range []string{`"/etc/passwd"`, `"/dev/shm"`, `"4"`, `"2"`} {
		if !strings.Contains(data, want) {
			t.Fatalf("generated policy missing %q:\n%s", want, data)
		}
	}
}

func TestCompileReportMarksNamespaceScopeAsPushedDown(t *testing.T) {
	report := CompileReport(contract.CollectionIntent{
		Behaviors: []string{"process.exec"},
		ScopeType: "namespace", ScopeSelector: "self",
		NamespaceSelectors: []contract.NamespaceSelector{
			{Namespace: "Pid", Values: []string{"4026533001"}},
			{Namespace: "Mnt", Values: []string{"4026533002"}},
		},
	})
	if !selectorReportContains(report.PushedDownSelectors, "process.exec", "scope.namespace") {
		t.Fatalf("namespace scope was not reported as pushed down: %+v", report)
	}
	if selectorReportContains(report.AgentSideSelectors, "process.exec", "scope.namespace") {
		t.Fatalf("namespace scope should not be reported as agent-side when resolved: %+v", report)
	}
	for _, warning := range report.Warnings {
		if strings.Contains(warning, "has no pushdown selectors") {
			t.Fatalf("namespace scope should count as a pushdown selector, warnings = %v", report.Warnings)
		}
	}
}

func TestCompileReportPushesProcessBinarySelectorsForNetworkAndFile(t *testing.T) {
	report := CompileReport(contract.CollectionIntent{
		Behaviors: []string{"network.connect", "file.write"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{
			{Behavior: "network.connect", BinaryPrefixes: []string{"/usr/bin"}, SocketFamilies: []string{"AF_INET"}, SocketAddrs: []string{"10.66.0.99"}, SocketPorts: []string{"443"}},
			{Behavior: "file.write", BinaryPrefixes: []string{"/usr/bin"}, FilePrefixes: []string{"/dev/shm"}},
		},
	})
	if report.Status != "ok" {
		t.Fatalf("report status = %q, unsupported = %+v", report.Status, report.UnsupportedSelectors)
	}
	if !selectorReportContains(report.PushedDownSelectors, "network.connect", "process.binary_prefix") {
		t.Fatalf("network binary selector was not pushed down: %+v", report.PushedDownSelectors)
	}
	if !selectorReportContains(report.AgentSideSelectors, "network.connect", "socket.addr") {
		t.Fatalf("network addr selector was not marked agent-side: %+v", report.AgentSideSelectors)
	}
	if !selectorReportContains(report.AgentSideSelectors, "network.connect", "socket.port") {
		t.Fatalf("network port selector was not marked agent-side: %+v", report.AgentSideSelectors)
	}
	if !selectorReportContains(report.PushedDownSelectors, "file.write", "process.binary_prefix") {
		t.Fatalf("file binary selector was not pushed down: %+v", report.PushedDownSelectors)
	}
	if !selectorReportContains(report.PushedDownSelectors, "file.write", "file.access") {
		t.Fatalf("file access selector was not pushed down: %+v", report.PushedDownSelectors)
	}
}

func TestTetraGetEventsArgsArePolicyScoped(t *testing.T) {
	args := tetraGetEventsArgs(contract.CollectionIntent{
		Behaviors: []string{"process.exec", "network.connect", "file.open"},
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{"getevents", "-o json", "--policy-names " + runtimeTracingPolicyName, "--event-types PROCESS_KPROBE"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args = %q, missing %q", joined, want)
		}
	}
}

func TestDefaultTetragonArgsAreSysArmorScoped(t *testing.T) {
	args := defaultTetragonArgs()
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--log-level warn",
		"--metrics-server ",
		"--health-server-address ",
		"--enable-tracing-policy-crd=false",
		"--enable-process-cred=false",
		"--enable-process-ns=false",
		"--enable-process-environment-variables=false",
		"--enable-k8s-api=false",
		"--enable-pod-annotations=false",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args = %q, missing %q", joined, want)
		}
	}
}

func TestBackendTetragonArgsEnableGRPCServer(t *testing.T) {
	backend := &Backend{
		EventTransport:   "grpc",
		ServerAddress:    "unix:///tmp/tetragon-test.sock",
		CgroupRate:       "1000",
		PprofAddress:     "127.0.0.1:6060",
		ProcessCacheSize: 4096,
		DataCacheSize:    128,
		EventQueueSize:   1024,
		RBQueueSize:      "8192",
	}
	joined := strings.Join(backend.tetragonArgs("/opt/sysarmor/agent/sensors/tetragon/current/bin/tetragon"), " ")
	for _, want := range []string{
		"--server-address unix:///tmp/tetragon-test.sock",
		"--cgroup-rate 1000",
		"--pprof-address 127.0.0.1:6060",
		"--process-cache-size 4096",
		"--data-cache-size 128",
		"--event-queue-size 1024",
		"--rb-queue-size 8192",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args = %q, missing %q", joined, want)
		}
	}
}

func selectorReportContains(reports []contract.CollectionSelectorReport, behavior, selector string) bool {
	for _, report := range reports {
		if report.Behavior == behavior && report.Selector == selector {
			return true
		}
	}
	return false
}
