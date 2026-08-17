package policy

import (
	"os"
	"path/filepath"
	"testing"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func TestParseCollectionIntent(t *testing.T) {
	intent, err := ParseCollectionIntent(`{"behaviors":["process.exec","process.exit","process.fork","file.open","file.write","file.chmod","network.connect"]}`, true)
	if err != nil {
		t.Fatalf("ParseCollectionIntent() error = %v", err)
	}
	if !intent.ObserveOnly {
		t.Fatal("ObserveOnly = false")
	}
	if len(intent.Behaviors) != 7 {
		t.Fatalf("Behaviors len = %d", len(intent.Behaviors))
	}
	if intent.Behaviors[0] != "process.exec" {
		t.Fatalf("first behavior = %v", intent.Behaviors[0])
	}
}

func TestLoadCollectionIntentFromRepoPolicy(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "test", "data", "policies", "collection.yaml")
	intent, err := LoadCollectionIntent(path, true)
	if err != nil {
		t.Fatalf("LoadCollectionIntent() error = %v", err)
	}
	if len(intent.Behaviors) == 0 {
		t.Fatal("Behaviors is empty")
	}
}

func TestBalancedPolicyResolvesContentRefs(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "test", "data", "policies", "collection-balanced.json")
	policy, err := ParseCollectionPolicyJSON(mustReadFile(t, path), true)
	if err != nil {
		t.Fatalf("ParseCollectionPolicyJSON() error = %v", err)
	}
	expanded, report, err := ExpandCollectionPolicyRefs(policy, CollectionContentSnapshot{
		ContextSets: map[string]CollectionValueSet{
			"ctx:credential-path-prefixes":  {Ref: "ctx:credential-path-prefixes", Version: "2026.06.18.1", ValueType: "path_prefix", Values: []string{"/etc/passwd", "/etc/shadow", "/root/.ssh", "/home/"}},
			"ctx:secret-volume-prefixes":    {Ref: "ctx:secret-volume-prefixes", Version: "2026.06.18.1", ValueType: "path_prefix", Values: []string{"/run/secrets", "/var/run/secrets"}},
			"ctx:payload-path-prefixes":     {Ref: "ctx:payload-path-prefixes", Version: "2026.06.18.1", ValueType: "path_prefix", Values: []string{"/dev/shm/", "/tmp/.sysarmor-attack/", "/var/tmp/.sysarmor-attack/"}},
			"ctx:persistence-path-prefixes": {Ref: "ctx:persistence-path-prefixes", Version: "2026.06.18.1", ValueType: "path_prefix", Values: []string{"/etc/cron", "/etc/systemd/system"}},
		},
		IOCPacks: map[string]CollectionValueSet{
			"ioc:c2-ip-feed":            {Ref: "ioc:c2-ip-feed", Version: "2026.06.18.1", ValueType: "ip", Values: []string{"10.66.0.99", "203.0.113.10"}},
			"ioc:c2-download-port-feed": {Ref: "ioc:c2-download-port-feed", Version: "2026.06.18.1", ValueType: "port", Values: []string{"8080"}},
			"ioc:c2-control-port-feed":  {Ref: "ioc:c2-control-port-feed", Version: "2026.06.18.1", ValueType: "port", Values: []string{"443", "8443"}},
		},
	})
	if err != nil {
		t.Fatalf("ExpandCollectionPolicyRefs() error = %v", err)
	}
	intent, err := CollectionPolicyIntent(expanded)
	if err != nil {
		t.Fatalf("CollectionPolicyIntent() error = %v", err)
	}
	if len(intent.Behaviors) != 6 || len(intent.MandatoryBehaviors) != 4 {
		t.Fatalf("behaviors = %v", intent.Behaviors)
	}
	if len(report.ResolvedRefs) != 8 {
		t.Fatalf("resolved refs = %+v", report.ResolvedRefs)
	}
}

func TestParseCollectionIntentRequiresJSONBehaviors(t *testing.T) {
	_, err := ParseCollectionIntent(`kinds: [SETUID]`, true)
	if err == nil {
		t.Fatal("ParseCollectionIntent() error = nil")
	}
}

func TestParseCollectionPolicyJSONBehaviorsAndFilters(t *testing.T) {
	policy, err := ParseCollectionPolicyJSON([]byte(`{
		"policy_id":"collection-a",
		"version":2,
		"behaviors":[
			{
				"id":"network.connect",
				"selectors":{
					"process":{"binary_prefixes":["/var/lib/app/plugins"]},
					"socket":{"families":["AF_INET"],"addrs":["10.66.0.99"],"addr_refs":["ioc:c2-ip-feed"],"ports":["443","8080"],"port_refs":["ioc:c2-control-port-feed"]}
				}
			},
			{
				"id":"file.write",
				"selectors":{
					"file":{"prefixes":["/dev/shm","/var/lib/app/plugins"],"prefix_refs":["ctx:payload-path-prefixes"]}
				}
			}
		],
		"scope_type":"container",
		"scope_selector":"abc123",
		"observe_only":true
	}`), true)
	if err != nil {
		t.Fatalf("ParseCollectionPolicyJSON() error = %v", err)
	}
	intent, err := CollectionPolicyIntent(policy)
	if err != nil {
		t.Fatalf("CollectionPolicyIntent() error = %v", err)
	}
	if len(intent.Behaviors) != 4 || len(intent.MandatoryBehaviors) != 4 {
		t.Fatalf("Behaviors = %v", intent.Behaviors)
	}
	if intent.Behaviors[0] != "process.exec" {
		t.Fatalf("first behavior = %v", intent.Behaviors[0])
	}
	if len(intent.BehaviorFilters) != 4 {
		t.Fatalf("BehaviorFilters = %+v", intent.BehaviorFilters)
	}
	network := intent.BehaviorFilters[3]
	if network.Behavior != "network.connect" || len(network.SocketFamilies) != 0 {
		t.Fatalf("network filter = %+v", network)
	}
	file := intent.BehaviorFilters[2]
	if file.Behavior != "file.write" || len(file.FilePrefixes) != 0 {
		t.Fatalf("file filter = %+v", file)
	}
	if intent.ScopeType != "container" || intent.ScopeSelector != "abc123" {
		t.Fatalf("scope = %s/%s", intent.ScopeType, intent.ScopeSelector)
	}
	if got := policy.BehaviorSpecs[0].Selectors.Socket.AddrRefs; len(got) != 1 || got[0] != "ioc:c2-ip-feed" {
		t.Fatalf("socket addr_refs = %v", got)
	}
	if got := policy.BehaviorSpecs[1].Selectors.File.PrefixRefs; len(got) != 1 || got[0] != "ctx:payload-path-prefixes" {
		t.Fatalf("file prefix_refs = %v", got)
	}
}

func TestExpandCollectionPolicyRefs(t *testing.T) {
	policy, err := ParseCollectionPolicyJSON([]byte(`{
		"behaviors":[
			{"id":"network.connect","selectors":{"socket":{"addr_refs":["ioc:c2-ip-feed"],"port_refs":["ioc:c2-control-port-feed"]}}},
			{"id":"file.write","selectors":{"file":{"prefix_refs":["ctx:payload-path-prefixes"]}}}
		]
	}`), true)
	if err != nil {
		t.Fatalf("ParseCollectionPolicyJSON() error = %v", err)
	}
	expanded, report, err := ExpandCollectionPolicyRefs(policy, CollectionContentSnapshot{
		ContextSets: map[string]CollectionValueSet{
			"ctx:payload-path-prefixes": {Ref: "ctx:payload-path-prefixes", Version: "2026.06.18.1", Digest: "ctx-digest", ValueType: "path_prefix", Values: []string{"/dev/shm/", "/var/tmp/.sysarmor-attack/"}},
		},
		IOCPacks: map[string]CollectionValueSet{
			"ioc:c2-ip-feed":           {Ref: "ioc:c2-ip-feed", Version: "2026.06.18.1", Digest: "ip-digest", ValueType: "ip", Values: []string{"203.0.113.10"}},
			"ioc:c2-control-port-feed": {Ref: "ioc:c2-control-port-feed", Version: "2026.06.18.1", Digest: "port-digest", ValueType: "port", Values: []string{"443", "8443"}},
		},
	})
	if err != nil {
		t.Fatalf("ExpandCollectionPolicyRefs() error = %v", err)
	}
	intent, err := CollectionPolicyIntent(expanded)
	if err != nil {
		t.Fatalf("CollectionPolicyIntent() error = %v", err)
	}
	if got := intent.BehaviorFilters[3].SocketAddrs; len(got) != 0 {
		t.Fatalf("socket addrs = %v", got)
	}
	if got := intent.BehaviorFilters[3].SocketPorts; len(got) != 0 {
		t.Fatalf("socket ports = %v", got)
	}
	if got := intent.BehaviorFilters[2].FilePrefixes; len(got) != 0 {
		t.Fatalf("file prefixes = %v", got)
	}
	if len(report.ResolvedRefs) != 3 {
		t.Fatalf("resolved refs = %+v", report.ResolvedRefs)
	}
}

func TestExpandCollectionPolicyRefsRejectsWrongValueType(t *testing.T) {
	policy, err := ParseCollectionPolicyJSON([]byte(`{
		"behaviors":[{"id":"network.connect","selectors":{"socket":{"addr_refs":["ioc:ports"]}}}]
	}`), true)
	if err != nil {
		t.Fatalf("ParseCollectionPolicyJSON() error = %v", err)
	}
	_, _, err = ExpandCollectionPolicyRefs(policy, CollectionContentSnapshot{
		IOCPacks: map[string]CollectionValueSet{
			"ioc:ports": {Ref: "ioc:ports", Version: "v1", Digest: "digest", ValueType: "port", Values: []string{"443"}},
		},
	})
	if err == nil {
		t.Fatal("ExpandCollectionPolicyRefs() error = nil")
	}
}

func TestCollectionPolicyFlatFieldsBecomeBehaviorFilters(t *testing.T) {
	policy, err := ParseCollectionPolicyJSON([]byte(`{
		"behaviors":["network.connect","file.write"],
		"file_prefixes":["/dev/shm"],
		"socket_families":["AF_INET"]
	}`), true)
	if err != nil {
		t.Fatalf("ParseCollectionPolicyJSON() error = %v", err)
	}
	intent, err := CollectionPolicyIntent(policy)
	if err != nil {
		t.Fatalf("CollectionPolicyIntent() error = %v", err)
	}
	if len(intent.BehaviorFilters) != 4 {
		t.Fatalf("BehaviorFilters = %+v", intent.BehaviorFilters)
	}
	if got := intent.BehaviorFilters[3].SocketFamilies; len(got) != 0 {
		t.Fatalf("network socket families = %v", got)
	}
	if got := intent.BehaviorFilters[2].FilePrefixes; len(got) != 0 {
		t.Fatalf("file prefixes = %v", got)
	}
}

func TestCollectionPolicyRejectsUnknownBehavior(t *testing.T) {
	_, err := CollectionPolicyIntent(domainpolicy.CollectionPolicy{Behaviors: []string{"unknown.behavior"}})
	if err == nil {
		t.Fatal("CollectionPolicyIntent() error = nil")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
