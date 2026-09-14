package tetragon

import (
	"slices"
	"strings"
	"testing"

	tetragonpb "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

func TestManagedGRPCAllowListSeparatesLifecycleFromRuntimeKprobes(t *testing.T) {
	filters := managedGRPCAllowList(contract.CollectionIntent{
		Behaviors: []string{"process.exec", "process.exit", "network.connect"},
	})

	if len(filters) != 2 {
		t.Fatalf("allow list filters = %d, want lifecycle and runtime kprobe filters", len(filters))
	}
	lifecycle, runtime := filters[0], filters[1]
	if !slices.Equal(lifecycle.GetEventSet(), []tetragonpb.EventType{
		tetragonpb.EventType_PROCESS_EXEC,
		tetragonpb.EventType_PROCESS_EXIT,
	}) || len(lifecycle.GetPolicyNames()) != 0 {
		t.Fatalf("lifecycle filter = %+v", lifecycle)
	}
	if !slices.Equal(runtime.GetEventSet(), []tetragonpb.EventType{tetragonpb.EventType_PROCESS_KPROBE}) ||
		!slices.Equal(runtime.GetPolicyNames(), []string{runtimeTracingPolicyName}) {
		t.Fatalf("runtime kprobe filter = %+v", runtime)
	}
}

func TestManagedGRPCAllowListPushesLifecycleBinaryPrefixes(t *testing.T) {
	filters := managedGRPCAllowList(contract.CollectionIntent{
		Behaviors: []string{"process.exec"},
		BehaviorFilters: []contract.CollectionBehaviorFilter{{
			Behavior: "process.exec", BinaryPrefixes: []string{"/opt/app/"},
		}},
	})

	if len(filters) != 1 || !slices.Equal(filters[0].GetBinaryRegex(), []string{`^/opt/app/`}) {
		t.Fatalf("lifecycle binary filter = %+v", filters)
	}
}

func TestCollectionContractReportsNativeLifecycleSources(t *testing.T) {
	mappings := map[string]string{}
	for _, capability := range CollectionCapabilities() {
		mappings[capability.Behavior] = capability.SensorMapping
	}
	if mappings["process.exec"] != "tetragon:process_exec" || mappings["process.exit"] != "tetragon:process_exit" {
		t.Fatalf("lifecycle capability mappings = %+v", mappings)
	}

	report := CompileReport(contract.CollectionIntent{Behaviors: []string{"process.exec", "process.exit"}})
	hooks := map[string]string{}
	for _, mapping := range report.BehaviorMappings {
		hooks[mapping.Behavior] = mapping.Hook
	}
	if hooks["process.exec"] != "process_exec" || hooks["process.exit"] != "process_exit" {
		t.Fatalf("lifecycle compile hooks = %+v", hooks)
	}
}

func TestTracingPolicyOmitsNativeLifecycleHooks(t *testing.T) {
	policy := string(buildTracingPolicy(contract.CollectionIntent{
		Behaviors: []string{"process.exec", "process.exit", "network.connect"},
	}))
	for _, legacyHook := range []string{"security_bprm_creds_from_file", "do_exit"} {
		if strings.Contains(policy, legacyHook) {
			t.Fatalf("tracing policy retained lifecycle kprobe %q:\n%s", legacyHook, policy)
		}
	}
	if !strings.Contains(policy, "security_socket_connect") {
		t.Fatalf("tracing policy lost runtime kprobe:\n%s", policy)
	}
}

func TestLifecycleOnlyDoesNotNeedTracingPolicy(t *testing.T) {
	intent := contract.CollectionIntent{Behaviors: []string{"process.exec", "process.exit", "process.fork"}}
	if needsTracingPolicy(intent) {
		t.Fatal("native process lifecycle must not install a kprobe tracing policy")
	}
}

func TestKprobeLifecycleEventsAreIgnored(t *testing.T) {
	for _, function := range []string{"security_bprm_creds_from_file", "do_exit"} {
		event := kprobeEventToSensor(envelope{}, kprobeEvent{
			Function:   function,
			PolicyName: runtimeTracingPolicyName,
			Process:    tetragonProcess{PID: 100, Binary: "/bin/bash"},
		}, "")
		if event != nil {
			t.Fatalf("legacy lifecycle kprobe %q emitted %q", function, event.GetBehavior())
		}
	}
}
