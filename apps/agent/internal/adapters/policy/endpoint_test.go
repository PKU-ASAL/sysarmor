package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	policyModel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestLoadEffectiveEndpointPolicyBootstrapsAndRestoresSQLite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(t.TempDir(), "policy.json")
	writeEndpointPolicy(t, path, `{"policy_id":"bootstrap","version":1,"collection":{"behaviors":["process.exec"]},"detection":{},"telemetry":{"max_batch_items":64},"response":{}}`)

	first, err := LoadEffectiveEndpointPolicy(t.Context(), store, path)
	if err != nil {
		t.Fatal(err)
	}
	writeEndpointPolicy(t, path, `{"policy_id":"changed-file","version":2,"collection":{"behaviors":["file.read"]},"detection":{},"telemetry":{},"response":{}}`)
	second, err := LoadEffectiveEndpointPolicy(t.Context(), store, path)
	if err != nil {
		t.Fatal(err)
	}
	if first.PolicyID != "bootstrap" || second.PolicyID != "bootstrap" || second.Version != 1 {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestEnsureStandaloneEndpointPolicyDoesNotReplaceManagedActivation(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	managed, _ := ParseEndpointPolicy([]byte(`{"policy_id":"managed","version":7,"collection":{"behaviors":["file.write"]},"detection":{},"telemetry":{},"response":{}}`))
	if err := store.SetEnrolling(t.Context(), endpointTestEnrollment()); err != nil {
		t.Fatal(err)
	}
	if err := ActivateManagedEndpointPolicy(t.Context(), store, managed); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	writeEndpointPolicy(t, path, `{"policy_id":"bootstrap-standalone","version":1,"collection":{"behaviors":["process.exec"]},"detection":{},"telemetry":{},"response":{}}`)
	initialized, err := EnsureStandaloneEndpointPolicy(t.Context(), store, path)
	if err != nil || !initialized {
		t.Fatalf("EnsureStandaloneEndpointPolicy() initialized=%t err=%v", initialized, err)
	}
	active, source, err := LoadActiveEndpointPolicy(t.Context(), store)
	standalone, ok, slotErr := LoadEndpointPolicy(t.Context(), store, localstore.PolicySourceStandalone)
	if err != nil || source != localstore.PolicySourceManaged || active.PolicyID != "managed" || slotErr != nil || !ok || standalone.PolicyID != "bootstrap-standalone" {
		t.Fatalf("active=%+v source=%q standalone=%+v ok=%t errors=%v/%v", active, source, standalone, ok, err, slotErr)
	}
}

func TestEffectiveEndpointPolicyPreservesStructuredCollectionBehaviors(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, err := ParseEndpointPolicy([]byte(`{
		"policy_id":"structured","version":1,
		"collection":{"behaviors":[{"id":"process.exec","selectors":{"process":{"binary_prefixes":["/bin/"]}}}]},
		"detection":{},"telemetry":{},"response":{}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveEffectiveEndpointPolicy(t.Context(), store, policy); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadEffectiveEndpointPolicy(t.Context(), store, filepath.Join(t.TempDir(), "unused.json"))
	if err != nil {
		t.Fatal(err)
	}
	intent, err := CollectionPolicyIntent(restored.Collection)
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.Behaviors) != 1 || intent.Behaviors[0] != "process.exec" || len(intent.BehaviorFilters[0].BinaryPrefixes) != 1 {
		t.Fatalf("restored collection intent = %+v", intent)
	}
}

func TestEndpointPolicySourcesPreserveStandaloneWhenManagedActivates(t *testing.T) {
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	standalone, _ := ParseEndpointPolicy([]byte(`{"policy_id":"standalone","version":1,"collection":{"behaviors":["process.exec"]},"detection":{},"telemetry":{},"response":{}}`))
	managed, _ := ParseEndpointPolicy([]byte(`{"policy_id":"managed","version":5,"collection":{"behaviors":["file.write"]},"detection":{},"telemetry":{},"response":{}}`))
	if err := SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), endpointTestEnrollment()); err != nil {
		t.Fatal(err)
	}
	if err := ActivateManagedEndpointPolicy(t.Context(), store, managed); err != nil {
		t.Fatal(err)
	}
	active, source, err := LoadActiveEndpointPolicy(t.Context(), store)
	if err != nil || source != localstore.PolicySourceManaged || active.PolicyID != "managed" {
		t.Fatalf("active=%+v source=%q err=%v", active, source, err)
	}
	preserved, ok, err := LoadEndpointPolicy(t.Context(), store, localstore.PolicySourceStandalone)
	if err != nil || !ok || preserved.PolicyID != "standalone" {
		t.Fatalf("standalone=%+v ok=%t err=%v", preserved, ok, err)
	}
}

func TestLoadEffectiveEndpointPolicyFollowsActivationAcrossRestart(t *testing.T) {
	root := t.TempDir()
	store, err := localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	standalone, _ := ParseEndpointPolicy([]byte(`{"policy_id":"standalone","version":1,"collection":{"behaviors":["process.exec"]},"detection":{},"telemetry":{},"response":{}}`))
	managed, _ := ParseEndpointPolicy([]byte(`{"policy_id":"managed","version":5,"collection":{"behaviors":["file.write"]},"detection":{},"telemetry":{},"response":{}}`))
	if err := SaveEffectiveEndpointPolicy(t.Context(), store, standalone); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEnrolling(t.Context(), endpointTestEnrollment()); err != nil {
		t.Fatal(err)
	}
	if err := ActivateManagedEndpointPolicy(t.Context(), store, managed); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = localstore.Open(t.Context(), localstore.Options{RootDir: root})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	active, err := LoadEffectiveEndpointPolicy(t.Context(), store, filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || active.PolicyID != "managed" {
		t.Fatalf("managed restart policy=%+v err=%v", active, err)
	}
	if _, err := store.PrepareUnenrollment(t.Context(), "completion-token", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmEnrollmentRevocation(t.Context(), "receipt-a", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteUnenrollment(t.Context(), "endpoint"); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadEffectiveEndpointPolicy(t.Context(), store, filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || restored.PolicyID != "standalone" {
		t.Fatalf("standalone restart policy=%+v err=%v", restored, err)
	}
}

func endpointTestEnrollment() localstore.Enrollment {
	return localstore.Enrollment{
		TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", CertificateSerial: "42",
		ManagerURL: "https://manager.example", GatewayAddress: "gateway", TLSCAPath: "/ca", TLSCertPath: "/cert", TLSKeyPath: "/key",
	}
}

func TestCollectionPolicyMarshalOmitsAbsentBehaviors(t *testing.T) {
	raw, err := json.Marshal(policyModel.CollectionPolicy{PolicyID: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"behaviors"`) {
		t.Fatalf("empty collection policy encoded behaviors: %s", raw)
	}
}

func TestParseEndpointPolicyRequiresAllSections(t *testing.T) {
	if _, err := ParseEndpointPolicy([]byte(`{"policy_id":"bad","version":1,"detection":{},"telemetry":{},"response":{}}`)); err == nil {
		t.Fatal("policy without collection accepted")
	}
}

func TestRepositoryDefaultEndpointPolicyParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "deployments", "agent", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ParseEndpointPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if policy.PolicyID != "standalone-default" || policy.Version != 1 {
		t.Fatalf("policy=%+v", policy)
	}
	if len(policy.Collection.Behaviors) == 0 || policy.Telemetry.MaxBatchItems != 256 {
		t.Fatalf("policy sections were not normalized: %+v", policy)
	}
	if len(policy.Detection.RuleSets) != 1 || policy.Detection.RuleSets[0].Ref != "ruleset:cep-endpoint" {
		t.Fatalf("default policy detection rulesets = %+v", policy.Detection.RuleSets)
	}
}

func writeEndpointPolicy(t *testing.T, path, document string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
}
