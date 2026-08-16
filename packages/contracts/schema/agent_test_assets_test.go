package schema

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSearchExactFieldsUseKeywordMappings(t *testing.T) {
	root := repositoryRoot(t)
	for file, fields := range map[string][]string{
		"events-v1.json":    {"behavior", "tenant_id"},
		"incidents-v1.json": {"id", "tenant_id"},
		"signals-v2.json":   {"tenant_id", "where", "stage", "detectorKind"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, "deployments", "opensearch", "mappings", file))
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Mappings struct {
				Properties map[string]struct {
					Type string `json:"type"`
				} `json:"properties"`
			} `json:"mappings"`
		}
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatalf("decode %s: %v", file, err)
		}
		for _, field := range fields {
			if got := document.Mappings.Properties[field].Type; got != "keyword" {
				t.Errorf("%s field %s type = %q, want keyword", file, field, got)
			}
		}
	}
}

func TestSignalMappingContainsNoTerminalField(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "deployments", "opensearch", "mappings", "signals-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Mappings struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"mappings"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if _, exists := document.Mappings.Properties["terminal"]; exists {
		t.Fatal("signals-v2 mapping still exposes terminal")
	}
}

var legacyAgentTestPatterns = []string{
	"/run/sysarmor/agent.sock",
	"\ndata_plane:",
	"\nagent:\n  id:",
	"\n  host_id:",
	"\n  tenant_id:",
	"\n  token:",
	"\nmanager:\n  transport: local",
	"\n  batch_size:",
	"\n  policy_path:",
}

func TestAgentTestAssetsUseCurrentSchema(t *testing.T) {
	root := repositoryRoot(t)
	testRoot := filepath.Join(root, "test")
	err := filepath.WalkDir(testRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".results" {
				return filepath.SkipDir
			}
			if path == filepath.Join(testRoot, "environments", "vm-topology", "deploy", "platform") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".sh" && filepath.Ext(path) != ".md" && filepath.Base(path) != "Makefile" {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, pattern := range legacyAgentTestPatterns {
			if strings.Contains(string(raw), pattern) {
				t.Errorf("legacy Agent test pattern %q in %s", pattern, filepath.ToSlash(path[len(root)+1:]))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	validateCoverageInventory(t, filepath.Join(testRoot, "contracts", "agent-test-coverage.tsv"))
}

func TestObsoleteAgentTestAssetsAreRemoved(t *testing.T) {
	root := repositoryRoot(t)
	for _, path := range []string{
		"configs/agent.fake.yaml",
		"test/shared/diagnostics/capture-container.sh",
		"test/suites/functional/endpoint/e2e-real-tetragon-owned-container.sh",
		"test/suites/functional/platform/e2e-gateway-local-ingest.sh",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); !os.IsNotExist(err) {
			t.Errorf("obsolete Agent test asset still exists: %s", path)
		}
	}
}

func TestVMDevelopmentInstallersUseCurrentContract(t *testing.T) {
	root := repositoryRoot(t)
	for _, path := range []string{
		"test/shared/diagnostics/capture-vm.sh",
		"test/suites/functional/endpoint/e2e-real-tetragon-owned-vm.sh",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		document := string(raw)
		for _, want := range []string{
			"SYSARMOR_CTL_BIN=/tmp/sysarmorctl.upload",
			"SYSARMOR_COLLECTION_POLICY=/tmp/sysarmor-deployments.upload/agent/policy.json",
			"  path: /etc/sysarmor/agent/policy.json",
			"/tmp/sysarmor-install-agent.log",
		} {
			if !strings.Contains(document, want) {
				t.Errorf("%s missing current installer contract %q", path, want)
			}
		}
	}
}

func TestAgentTestsApplyOnlyAdditionalTestContent(t *testing.T) {
	root := repositoryRoot(t)
	for path, want := range map[string]string{
		"test/suites/functional/endpoint/e2e-real-tetragon-owned-vm.sh": `vagrant upload "$REPO/test/data/content"`,
		"test/suites/performance/endpoint/run.sh":                       `SYSARMOR_BENCH_CONTENT_DIR:-test/data/content`,
		"test/suites/performance/endpoint/lifecycle.sh":                 `SYSARMOR_BENCH_CONTENT_DIR:-test/data/content`,
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Errorf("%s missing product content source %q", path, want)
		}
	}
	e2e, err := os.ReadFile(filepath.Join(root, "test", "suites", "functional", "endpoint", "e2e-real-tetragon-owned-vm.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(e2e), "ioc-c2-port-feed.json") {
		t.Error("endpoint E2E still applies the removed combined C2 port feed")
	}
}

func TestPlatformHarnessConfiguresManagerJWT(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Join(root, "test", "shared", "harness", "lib", "common.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	for _, want := range []string{
		"tools/pki/gen-manager-jwt.sh",
		"tools/auth/issue-manager-jwt.sh",
		"--jwt-public-key",
		"export SYSARMOR_MANAGER_JWT",
		"sa_manager_curl()",
		"Authorization: Bearer",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("platform harness missing Manager JWT contract %q", want)
		}
	}
}

func TestContainerTopologyUsesProtectedContainerInstaller(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "environments", "container", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	for _, want := range []string{
		"  node-a:\n",
		"    privileged: true",
		"/sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro",
		"/sys/fs/bpf:/sys/fs/bpf",
		"SYSARMOR_AGENT_CA_CERT:",
		"SYSARMOR_GRPC_TLS_CERT:",
		"SYSARMOR_GRPC_TLS_KEY:",
		"SYSARMOR_GRPC_CLIENT_CA:",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("container topology missing %q", want)
		}
	}
	if strings.Contains(document, "SYSARMOR_GRPC_REQUIRE_CLIENT_CERT") {
		t.Error("container topology still configures optional Gateway client certificate verification")
	}
	if strings.Contains(document, "  tetragon:\n") {
		t.Error("container topology still defines a Tetragon sidecar")
	}
	runner, err := os.ReadFile(filepath.Join(root, "test", "suites", "functional", "topology", "scenario-container.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runner), `--profile linux-container`) || !strings.Contains(string(runner), `--artifact-id "$artifact_id"`) {
		t.Error("container topology does not install the Manager-bound linux-container artifact")
	}
	if strings.Contains(string(runner), "--artifact-url") {
		t.Error("container topology bypasses Manager artifact binding")
	}
	for _, want := range []string{
		`EVENT_BEHAVIOR=`,
		`--behavior "$EVENT_BEHAVIOR" --limit 100`,
		`POLICY_ID="default-edr-policy"`,
		`--label policy_id="$POLICY_ID"`,
	} {
		if !strings.Contains(string(runner), want) {
			t.Errorf("container topology event readiness query missing %q", want)
		}
	}
}

func TestEndpointPerformanceBuildsAllBinaries(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "suites", "performance", "endpoint", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	runner := string(raw)
	if !strings.Contains(runner, `make -C "$REPO" build-binary`) {
		t.Error("endpoint performance runner does not use the all-binary build target")
	}
	if strings.Contains(runner, `make -C "$REPO" build`+"\n") {
		t.Error("endpoint performance runner still uses the service-specific build target")
	}
}

func TestVMPerformanceInstallerSuppliesCtlBinary(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "shared", "vm", "sync-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "SYSARMOR_CTL_BIN=/tmp/sysarmorctl.upload") {
		t.Error("VM Agent sync does not bind the uploaded sysarmorctl binary to the installer")
	}
}

func TestEndpointPerformanceDiscoversRuntimeIdentity(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "suites", "performance", "endpoint", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	runner := string(raw)
	for _, want := range []string{`agent health`, `.agentId // .agent_id`, `.tenantId // .tenant_id`} {
		if !strings.Contains(runner, want) {
			t.Errorf("endpoint performance runner does not discover runtime identity with %q", want)
		}
	}
	for _, legacy := range []string{"SYSARMOR_BENCH_AGENT_ID:-vm-owned-tetragon", "SYSARMOR_BENCH_TENANT_ID:-default"} {
		if strings.Contains(runner, legacy) {
			t.Errorf("endpoint performance runner still defines unused identity default %q", legacy)
		}
	}
}

func TestStandaloneVMToolsDiscoverRuntimeIdentity(t *testing.T) {
	root := repositoryRoot(t)
	for _, path := range []string{
		"test/shared/diagnostics/capture-vm.sh",
		"test/shared/diagnostics/diagnose-tetragon-vm.sh",
		"test/shared/recorder/recorder-vm.sh",
		"test/suites/performance/endpoint/lifecycle.sh",
		"test/suites/functional/endpoint/e2e-real-tetragon-owned-vm.sh",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		document := string(raw)
		for _, want := range []string{`agent health`, `.agentId // .agent_id`, `.tenantId // .tenant_id`} {
			if !strings.Contains(document, want) {
				t.Errorf("%s does not discover runtime identity with %q", path, want)
			}
		}
		for _, legacy := range []string{"--agent-id vm-owned-tetragon", "--agent-id vm-node-a"} {
			if strings.Contains(document, legacy) {
				t.Errorf("%s still uses legacy local identity %q", path, legacy)
			}
		}
	}
}

func TestVMRecorderUsesRuntimeStreamCursors(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "shared", "recorder", "recorder-vm.sh"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := string(raw)
	for _, want := range []string{
		`AGENT_SOCK=\"\${2:-/run/sysarmor/agent/control.sock}\"`,
		"streams.eventNewestSequence",
		"streams.signalNewestSequence",
		"ensure_watchers",
	} {
		if !strings.Contains(recorder, want) {
			t.Errorf("VM recorder does not satisfy runtime watcher contract %q", want)
		}
	}
}

func TestEndpointPerformancePropagatesWorkloadFailures(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "suites", "performance", "endpoint", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	runner := string(raw)
	for _, legacy := range []string{
		`> "$policy_out/workload.out" 2>"$policy_out/workload.err" || true`,
		`> "$policy_out/scenario.out" 2>"$policy_out/scenario.err" || true`,
		`wait "$workload_pid" || true`,
	} {
		if strings.Contains(runner, legacy) {
			t.Errorf("endpoint performance runner still suppresses failure with %q", legacy)
		}
	}
}

func TestTestMakefileProvidesActionableDoctor(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "test", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(raw)
	for _, want := range []string{
		"doctor:",
		"vagrant plugin list",
		"vagrant-libvirt",
		"SYSARMOR_TETRAGON_ARCHIVE",
		"export SYSARMOR_TETRAGON_ARCHIVE",
		".scratchpad/.cache/tetragon-v1.7.0-amd64.tar.gz",
		"修复:",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("test Makefile doctor missing %q", want)
		}
	}
}

func TestRootMakefileDelegatesTestCommands(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	makefile := string(raw)
	for _, want := range []string{
		"test-help:",
		"test-doctor:",
		"test-unit:",
		"test-performance:",
		"$(MAKE) -C test doctor",
		"$(or $(SYSARMOR_TETRAGON_ARCHIVE)",
		"SYSARMOR_BENCH_PROFILE=$(PROFILE)",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("root Makefile test delegates missing %q", want)
		}
	}
}

func validateCoverageInventory(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	seen := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		if line == 1 {
			continue
		}
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 5 || slicesContainEmpty(fields) {
			t.Errorf("%s:%d: expected five non-empty tab-separated fields", path, line)
			continue
		}
		key := fields[0] + "\t" + fields[2]
		if seen[key] {
			t.Errorf("%s:%d: duplicate source/assertion %q", path, line, key)
		}
		seen[key] = true
		if fields[4] != "legacy" && fields[4] != "covered" {
			t.Errorf("%s:%d: invalid status %q", path, line, fields[4])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func slicesContainEmpty(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
