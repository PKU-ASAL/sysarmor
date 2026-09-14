package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/grpc"
)

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = lis
	server.Start()
	return server
}

func TestQueryAgentsFilters(t *testing.T) {
	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_, _ = fmt.Fprintln(w, "[]")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{"manager", "agents", "list", "--tenant-id", "default", "--scope-type", "container", "--scope-selector", "abc123", "--health-status", "ok"}); err != nil {
		t.Fatalf("query() error = %v", err)
	}
	want := "/api/v1/agents?health_status=ok&scope_selector=abc123&scope_type=container&tenant_id=default"
	if gotPath != want {
		t.Fatalf("path = %q, want %q", gotPath, want)
	}
}

func TestTopLevelManagerCommandsRequireManagerNamespace(t *testing.T) {
	if _, err := query("http://127.0.0.1:9443", []string{"agents"}); err == nil || !strings.Contains(err.Error(), "manager namespace") {
		t.Fatalf("query old top-level command error = %v", err)
	}
}

func TestLocalEnrollmentCommandsUseAgentSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go server.Serve(lis)
	defer server.Stop()

	args := []string{"enroll", "--manager-url", "https://manager.example", "--token", "secret", "--upload-history"}
	if _, err := queryLocalAgentWithManager(socketPath, "", args); err != nil {
		t.Fatal(err)
	}
	if fake.enrollReq.GetManagerUrl() != "https://manager.example" || fake.enrollReq.GetEnrollmentToken() != "secret" || !fake.enrollReq.GetUploadHistory() {
		t.Fatalf("enroll request=%+v", fake.enrollReq)
	}
	if fake.enrollReq.GetTenantId() != "" || fake.enrollReq.GetAgentId() != "" || fake.enrollReq.GetGatewayAddress() != "" {
		t.Fatalf("client supplied Manager-owned enrollment fields: %+v", fake.enrollReq)
	}
	if _, err := queryLocalAgentWithManager(socketPath, "", []string{"unenroll"}); err != nil || fake.unenrollReq == nil {
		t.Fatalf("unenroll err=%v req=%+v", err, fake.unenrollReq)
	}
}

func TestLocalEnrollmentWaitsForPendingPolicyActivation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{enrollStatus: "pending", healthModes: []string{"enrolling", "managed"}}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go server.Serve(lis)
	defer server.Stop()

	body, err := queryLocalAgentWithManager(socketPath, "", []string{"enroll", "--manager-url", "https://manager.example", "--token", "secret", "--timeout", "1s"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"status":"applied"`) || fake.healthCalls != 2 {
		t.Fatalf("body=%s health_calls=%d", body, fake.healthCalls)
	}
}

func TestEnrollmentCommandTimeoutDefaultsToPolicyActivationWindow(t *testing.T) {
	if got := commandTimeout([]string{"enroll"}, 5*time.Second); got != 60*time.Second {
		t.Fatalf("enroll timeout = %s, want 60s", got)
	}
	if got := commandTimeout([]string{"unenroll"}, 5*time.Second); got != 60*time.Second {
		t.Fatalf("unenroll timeout = %s, want 60s", got)
	}
	if got := commandTimeout([]string{"unenroll", "--timeout", "90s"}, 5*time.Second); got != 90*time.Second {
		t.Fatalf("explicit unenroll timeout = %s, want 90s", got)
	}
	if got := commandTimeout([]string{"agent", "health"}, 5*time.Second); got != 5*time.Second {
		t.Fatalf("agent health timeout = %s, want 5s", got)
	}
}

func TestHealthJSONEmitsZeroCandidateLifecycleCounters(t *testing.T) {
	raw, err := marshalHealthJSON(&controlplanev1.HealthResponse{
		Detection: &controlplanev1.DetectionRuntimeHealth{
			Learning: &controlplanev1.LearningRuntimeHealth{Candidates: &controlplanev1.CandidateLifecycleRuntimeHealth{}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, field := range []string{"created", "spooled", "gatewayAccepted", "gatewayDuplicateAck", "contractRejected", "gatewayRejected"} {
		if !strings.Contains(text, `"`+field+`":"0"`) {
			t.Fatalf("health JSON does not contain explicit %s zero: %s", field, text)
		}
	}
}

func TestLocalEnrollmentReadsTokenFile(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("secret-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := parseEnrollmentArgs("", []string{
		"enroll", "--manager-url", "https://manager.example", "--token-file", tokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.managerURL != "https://manager.example" || opts.token != "secret-from-file" {
		t.Fatalf("enrollment options = %+v", opts)
	}
	if _, err := parseEnrollmentArgs("", []string{
		"enroll", "--manager-url", "https://manager.example", "--token", "a", "--token-file", tokenPath,
	}); err == nil {
		t.Fatal("combined --token and --token-file accepted")
	}
}

func TestLocalEnrollmentRejectsManagerOwnedIdentityFlags(t *testing.T) {
	_, err := parseEnrollmentArgs("", []string{
		"enroll", "--manager-url", "https://manager.example", "--token", "secret",
		"--agent-id", "agent-a",
	})
	if err == nil || !strings.Contains(err.Error(), "configured by the Manager enrollment") {
		t.Fatalf("legacy enrollment flag error = %v", err)
	}
}

func TestQueryPolicyCommands(t *testing.T) {
	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_, _ = fmt.Fprintln(w, "{}")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{"manager", "rules", "list", "--where", "cloud"}); err != nil {
		t.Fatalf("rules query error = %v", err)
	}
	if gotPath != "/api/v1/rules?where=cloud" {
		t.Fatalf("rules path = %q", gotPath)
	}

	if _, err := query(server.URL, []string{"manager", "policies", "effective", "--tenant-id", "default", "--agent-id", "agent-a", "--scope-type", "container", "--scope-selector", "abc123"}); err != nil {
		t.Fatalf("effective-policy query error = %v", err)
	}
	want := "/api/v1/effective-policy?agent_id=agent-a&scope_selector=abc123&scope_type=container&tenant_id=default"
	if gotPath != want {
		t.Fatalf("effective-policy path = %q, want %q", gotPath, want)
	}
}

func TestQueryRarityBaseline(t *testing.T) {
	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_, _ = fmt.Fprintln(w, "{}")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{"manager", "rarity", "baseline", "--workload", "container:checkout-api", "--signal", "download_by_lolbin"}); err != nil {
		t.Fatalf("rarity-baseline query error = %v", err)
	}
	want := "/api/v1/rarity-baseline?signal=download_by_lolbin&workload=container%3Acheckout-api"
	if gotPath != want {
		t.Fatalf("path = %q, want %q", gotPath, want)
	}
}

func TestQuerySignalsUsesStage(t *testing.T) {
	var gotPath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		_, _ = fmt.Fprintln(w, "[]")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{"manager", "signals", "--stage", "candidate"}); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/signals?stage=candidate" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestEvidencePullbackCommand(t *testing.T) {
	var gotMethod string
	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.String()
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if err := json.Unmarshal(body, &gotBody); err != nil {
				t.Fatalf("decode body: %v body=%s", err, string(body))
			}
		}
		_, _ = fmt.Fprintln(w, "{}")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{
		"manager", "evidence", "pullbacks",
		"--create",
		"--request-id", "evpb-a",
		"--tenant-id", "default",
		"--agent-id", "agent-a",
		"--incident-id", "inc-a",
		"--label", "scenario=apt-fileless-c2",
		"--target", "process:p1",
		"--reason", "collect process tree",
	}); err != nil {
		t.Fatalf("create query error = %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/evidence-pullbacks" {
		t.Fatalf("create method/path = %s %s", gotMethod, gotPath)
	}
	for key, want := range map[string]string{
		"request_id":  "evpb-a",
		"tenant_id":   "default",
		"agent_id":    "agent-a",
		"incident_id": "inc-a",
		"target":      "process:p1",
		"reason":      "collect process tree",
	} {
		if gotBody[key] != want {
			t.Fatalf("body[%s] = %v, want %s", key, gotBody[key], want)
		}
	}
	labels, ok := gotBody["labels"].(map[string]any)
	if !ok || labels["scenario"] != "apt-fileless-c2" {
		t.Fatalf("body labels = %#v, want scenario label", gotBody["labels"])
	}

	if _, err := query(server.URL, []string{"manager", "evidence", "pullbacks", "--tenant-id", "default", "--agent-id", "agent-a"}); err != nil {
		t.Fatalf("list query error = %v", err)
	}
	wantPath := "/api/v1/evidence-pullbacks?agent_id=agent-a&tenant_id=default"
	if gotMethod != http.MethodGet || gotPath != wantPath {
		t.Fatalf("list method/path = %s %s, want GET %s", gotMethod, gotPath, wantPath)
	}
}

func TestManagerNamespaceControlCommands(t *testing.T) {
	dir := t.TempDir()
	contentPath := filepath.Join(dir, "ioc.json")
	if err := os.WriteFile(contentPath, []byte(`{"api_version":"sysarmor.content/v1","kind":"iocpack","metadata":{"id":"ioc:test","version":"v1"},"spec":{"value_type":"ip","values":["10.0.0.1"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var gotMethod string
	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.String()
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if err := json.Unmarshal(body, &gotBody); err != nil {
				t.Fatalf("decode body: %v body=%s", err, string(body))
			}
		}
		_, _ = fmt.Fprintln(w, "{}")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{"manager", "control-commands", "list", "--tenant", "default", "--agent", "agent-a", "--type", "content_update"}); err != nil {
		t.Fatalf("control command list error = %v", err)
	}
	wantPath := "/api/v1/control-commands?agent_id=agent-a&tenant_id=default&type=content_update"
	if gotMethod != http.MethodGet || gotPath != wantPath {
		t.Fatalf("list method/path = %s %s, want GET %s", gotMethod, gotPath, wantPath)
	}

	if _, err := query(server.URL, []string{
		"manager", "control-commands", "create", "content",
		"--command-id", "ctrl-content",
		"--tenant", "default",
		"--agent", "agent-a",
		"--file", contentPath,
		"--actor", "operator",
		"--reason", "refresh ioc",
	}); err != nil {
		t.Fatalf("control command create error = %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/control-commands" {
		t.Fatalf("create method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["type"] != "content_update" || gotBody["command_id"] != "ctrl-content" || gotBody["tenant_id"] != "default" || gotBody["agent_id"] != "agent-a" || gotBody["actor"] != "operator" || gotBody["reason"] != "refresh ioc" {
		t.Fatalf("create body = %#v", gotBody)
	}
	payload, ok := gotBody["payload_json"].(map[string]any)
	if !ok || payload["kind"] != "iocpack" {
		t.Fatalf("payload_json = %#v", gotBody["payload_json"])
	}

	if _, err := query(server.URL, []string{
		"manager", "control-commands", "cancel",
		"--command-id", "ctrl-content",
		"--tenant", "default",
		"--agent", "agent-a",
		"--actor", "operator",
		"--reason", "bad rollout",
	}); err != nil {
		t.Fatalf("control command cancel error = %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/control-commands" {
		t.Fatalf("cancel method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["action"] != "cancel" || gotBody["command_id"] != "ctrl-content" || gotBody["tenant_id"] != "default" || gotBody["agent_id"] != "agent-a" || gotBody["actor"] != "operator" || gotBody["reason"] != "bad rollout" {
		t.Fatalf("cancel body = %#v", gotBody)
	}
}

func TestManagerNamespacePolicyAssignDownlink(t *testing.T) {
	var gotMethod string
	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.String()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &gotBody); err != nil {
			t.Fatalf("decode body: %v body=%s", err, string(body))
		}
		_, _ = fmt.Fprintln(w, "{}")
	}))
	defer server.Close()

	if _, err := query(server.URL, []string{
		"manager", "policies", "assign",
		"--tenant", "default",
		"--agent", "agent-a",
		"--policy-id", "balanced",
		"--version", "3",
		"--downlink",
		"--command-id", "ctrl-policy",
		"--actor", "operator",
		"--reason", "deploy now",
	}); err != nil {
		t.Fatalf("policy assign error = %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/policy-assignments" {
		t.Fatalf("assign method/path = %s %s", gotMethod, gotPath)
	}
	if gotBody["tenant_id"] != "default" || gotBody["agent_id"] != "agent-a" || gotBody["policy_id"] != "balanced" || gotBody["downlink"] != true || gotBody["command_id"] != "ctrl-policy" {
		t.Fatalf("assign body = %#v", gotBody)
	}
	if gotBody["policy_version"] != float64(3) {
		t.Fatalf("policy_version = %#v", gotBody["policy_version"])
	}
}

func TestQueryLocalAgentCapabilityOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, &fakeAgentControlServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	body, err := queryLocalAgent(socketPath, []string{"agent", "capability", "--tenant-id", "default", "--agent-id", "agent-a"})
	if err != nil {
		t.Fatalf("queryLocalAgent() error = %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v body=%s", err, string(body))
	}
	if got["agentId"] != "agent-a" || got["tenantId"] != "default" {
		t.Fatalf("body = %s", string(body))
	}
	sensor, ok := got["sensor"].(map[string]any)
	if !ok || sensor["backend"] != "fake" || sensor["supportsExec"] != true {
		t.Fatalf("sensor = %#v body=%s", got["sensor"], string(body))
	}
}

func TestQueryLocalAgentPolicyApplyOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	policyFile := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyFile, []byte(`{"policy_id":"local","version":2,"collection":{},"detection":{},"telemetry":{},"response":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := queryLocalAgent(socketPath, []string{
		"policy", "apply",
		"--tenant-id", "default",
		"--agent-id", "agent-a",
		"--type", "endpoint",
		"--file", policyFile,
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("queryLocalAgent() error = %v", err)
	}
	if fake.applyReq == nil || fake.applyReq.GetPolicyType() != "endpoint" || !fake.applyReq.GetDryRun() {
		t.Fatalf("apply request = %+v", fake.applyReq)
	}
	if fake.applyReq.GetContext().GetAgentId() != "agent-a" || fake.applyReq.GetPolicyJson() == "" {
		t.Fatalf("apply request = %+v", fake.applyReq)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v body=%s", err, string(body))
	}
	if got["status"] != "validated" || got["policyId"] != "local" {
		t.Fatalf("body = %s", string(body))
	}
}

func TestQueryLocalAgentPolicyApplyCollectionFlags(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	_, err = queryLocalAgent(socketPath, []string{
		"policy", "apply", "collection",
		"--tenant-id", "default",
		"--agent-id", "agent-a",
		"--behavior", "network.connect",
		"--behavior", "file.write",
		"--file-prefix", "/dev/shm",
		"--socket-family", "AF_INET",
	})
	if err != nil {
		t.Fatalf("queryLocalAgent() error = %v", err)
	}
	if fake.applyReq == nil || fake.applyReq.GetPolicyType() != "collection" {
		t.Fatalf("apply request = %+v", fake.applyReq)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(fake.applyReq.GetPolicyJson()), &payload); err != nil {
		t.Fatalf("decode policy json: %v", err)
	}
	behaviors, ok := payload["behaviors"].([]any)
	if !ok || len(behaviors) != 2 {
		t.Fatalf("behaviors = %#v", payload["behaviors"])
	}
	first, ok := behaviors[0].(map[string]any)
	if !ok || first["id"] != "network.connect" {
		t.Fatalf("first behavior = %#v", behaviors[0])
	}
	second, ok := behaviors[1].(map[string]any)
	if !ok || second["id"] != "file.write" {
		t.Fatalf("second behavior = %#v", behaviors[1])
	}
	selectors, ok := second["selectors"].(map[string]any)
	if !ok {
		t.Fatalf("second selectors = %#v", second["selectors"])
	}
	file, ok := selectors["file"].(map[string]any)
	if !ok {
		t.Fatalf("file selector = %#v", selectors["file"])
	}
	prefixes, ok := file["prefixes"].([]any)
	if !ok || len(prefixes) != 1 || prefixes[0] != "/dev/shm" {
		t.Fatalf("file prefixes = %#v", file["prefixes"])
	}
}

func TestQueryLocalAgentWatchStreamsOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, &fakeAgentControlServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	eventBody, err := queryLocalAgent(socketPath, []string{"event", "watch", "--include-recent", "--limit", "1", "--behavior", "process.exec"})
	if err != nil {
		t.Fatalf("event watch error = %v", err)
	}
	if lines := nonEmptyLines(string(eventBody)); len(lines) != 1 {
		t.Fatalf("event body = %s", string(eventBody))
	}
	signalBody, err := queryLocalAgent(socketPath, []string{"signal", "watch", "--include-recent", "--limit", "1", "--rule-id", "payload_dropped", "--where", "endpoint"})
	if err != nil {
		t.Fatalf("signal watch error = %v", err)
	}
	if lines := nonEmptyLines(string(signalBody)); len(lines) != 1 {
		t.Fatalf("signal body = %s", string(signalBody))
	}
}

func TestQueryLocalAgentWatchFilterArgs(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	if _, err := queryLocalAgent(socketPath, []string{
		"event", "watch",
		"--include-recent",
		"--limit", "1",
		"--after-seq", "42",
		"--since", "2026-06-19T01:02:03Z",
		"--until", "2026-06-19T02:02:03Z",
		"--label", "benchmark_run=run-a",
		"--label", "workload=business-normal",
	}); err != nil {
		t.Fatalf("event watch error = %v", err)
	}
	if fake.watchEventReq.GetFilter().GetAfterSequence() != 42 {
		t.Fatalf("event filter = %+v", fake.watchEventReq.GetFilter())
	}
	if fake.watchEventReq.GetFilter().GetSinceObservedAt() != "2026-06-19T01:02:03Z" || fake.watchEventReq.GetFilter().GetUntilObservedAt() != "2026-06-19T02:02:03Z" {
		t.Fatalf("event filter time window = %+v", fake.watchEventReq.GetFilter())
	}
	if fake.watchEventReq.GetFilter().GetLabels()["benchmark_run"] != "run-a" || fake.watchEventReq.GetFilter().GetLabels()["workload"] != "business-normal" {
		t.Fatalf("event filter labels = %+v", fake.watchEventReq.GetFilter().GetLabels())
	}

	if _, err := queryLocalAgent(socketPath, []string{
		"signal", "watch",
		"--include-recent",
		"--limit", "1",
		"--label", "policy_profile=collection-balanced",
	}); err != nil {
		t.Fatalf("signal watch error = %v", err)
	}
	if fake.watchSignalReq.GetFilter().GetLabels()["policy_profile"] != "collection-balanced" {
		t.Fatalf("signal filter labels = %+v", fake.watchSignalReq.GetFilter().GetLabels())
	}
}

func TestQueryLocalAgentSignalWatchIncludesEvents(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	body, err := queryLocalAgent(socketPath, []string{"signal", "watch", "--include-recent", "--limit", "1", "--rule-id", "payload_dropped", "--where", "endpoint", "--include-events"})
	if err != nil {
		t.Fatalf("signal watch error = %v", err)
	}
	lines := nonEmptyLines(string(body))
	if len(lines) != 1 {
		t.Fatalf("signal body = %s", string(body))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("decode body: %v body=%s", err, string(body))
	}
	events, ok := got["eventFrames"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("eventFrames = %#v body=%s", got["eventFrames"], string(body))
	}
	if fake.getEventReq == nil || fake.getEventReq.GetEventId() != "ev-a" {
		t.Fatalf("get event request = %+v", fake.getEventReq)
	}
}

func TestQueryLocalAgentEventGetOverUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	body, err := queryLocalAgent(socketPath, []string{"event", "get", "--event-id", "ev-a"})
	if err != nil {
		t.Fatalf("event get error = %v", err)
	}
	if fake.getEventReq == nil || fake.getEventReq.GetEventId() != "ev-a" {
		t.Fatalf("get event request = %+v", fake.getEventReq)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v body=%s", err, string(body))
	}
	frame := got["frame"].(map[string]any)
	event := frame["event"].(map[string]any)
	if event["id"] != "ev-a" {
		t.Fatalf("body = %s", string(body))
	}
}

func TestQueryLocalAgentDebugProfileWritesOutput(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	outPath := filepath.Join(dir, "agent.cpu.pb.gz")
	body, err := queryLocalAgent(socketPath, []string{"debug", "profile", "cpu", "--seconds", "1", "--label", "workload", "--output", outPath})
	if err != nil {
		t.Fatalf("debug profile error = %v", err)
	}
	if fake.debugProfileReq == nil || fake.debugProfileReq.GetProfileType() != "cpu" || fake.debugProfileReq.GetSeconds() != 1 || fake.debugProfileReq.GetLabel() != "workload" {
		t.Fatalf("debug profile request = %+v", fake.debugProfileReq)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read profile output: %v", err)
	}
	if string(data) != "fake-profile" {
		t.Fatalf("profile output = %q", string(data))
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode body: %v body=%s", err, string(body))
	}
	if got["profile"] != nil || got["profileType"] != "cpu" || got["label"] != "workload" {
		t.Fatalf("body = %s", string(body))
	}
}

func TestQueryLocalAgentContentCommands(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")
	contentPath := filepath.Join(dir, "ioc.json")
	if err := os.WriteFile(contentPath, []byte(`{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-ip-feed","version":"2026.06.17.1"},
		"spec":{"value_type":"ip","values":["203.0.113.10"]}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	fake := &fakeAgentControlServer{}
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, fake)
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	if _, err := queryLocalAgent(socketPath, []string{"content", "apply", "--file", contentPath, "--allow-unsigned"}); err != nil {
		t.Fatalf("content apply error = %v", err)
	}
	if fake.contentReq == nil || !fake.contentReq.GetAllowUnsigned() || !strings.Contains(fake.contentReq.GetContentJson(), "ioc:c2-ip-feed") {
		t.Fatalf("content request = %+v", fake.contentReq)
	}
	if _, err := queryLocalAgent(socketPath, []string{"content", "list", "--kind", "iocpack"}); err != nil {
		t.Fatalf("content list error = %v", err)
	}
	if _, err := queryLocalAgent(socketPath, []string{"content", "get", "--ref", "ioc:c2-ip-feed"}); err != nil {
		t.Fatalf("content get error = %v", err)
	}
}

func TestContentDiffBuildsPatch(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	if err := os.WriteFile(oldPath, []byte(`{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-control-port-feed","version":"v1"},
		"spec":{"value_type":"port","values":["443","8443"]}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(`{
		"api_version":"sysarmor.content/v1",
		"kind":"iocpack",
		"metadata":{"id":"ioc:c2-control-port-feed","version":"v2"},
		"spec":{"value_type":"port","values":["9443","8443"]}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := contentDiff([]string{"content", "diff", "--file", oldPath, "--file", newPath, "--version", "v2"})
	if err != nil {
		t.Fatal(err)
	}
	var patch map[string]any
	if err := json.Unmarshal(body, &patch); err != nil {
		t.Fatal(err)
	}
	spec := patch["spec"].(map[string]any)
	ops := spec["ops"].([]any)
	if len(ops) != 2 {
		t.Fatalf("ops = %#v", ops)
	}
}

func TestQueryLocalAgentWatchReturnsPartialFramesOnTimeout(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, &blockingAgentControlServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	body, err := queryLocalAgent(socketPath, []string{"signal", "watch", "--include-recent", "--limit", "200", "--timeout", "10ms"})
	if err != nil {
		t.Fatalf("signal watch partial timeout error = %v", err)
	}
	if lines := nonEmptyLines(string(body)); len(lines) != 1 {
		t.Fatalf("signal body = %s", string(body))
	}
}

func TestStreamingWatchWritesFramesBeforeTimeout(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(server, &blockingAgentControlServer{})
	go func() {
		_ = server.Serve(lis)
	}()
	defer server.Stop()

	oldStdout := os.Stdout
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writeFile
	err = streamLocalAgent(socketPath, []string{"signal", "watch", "--timeout", "10ms"})
	_ = writeFile.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("stream signal watch error = %v", err)
	}
	body, err := io.ReadAll(readFile)
	if err != nil {
		t.Fatal(err)
	}
	if lines := nonEmptyLines(string(body)); len(lines) != 1 {
		t.Fatalf("stream signal body = %s", string(body))
	}
}

func TestWatchWithLimitStillUsesStreamingOutput(t *testing.T) {
	for _, args := range [][]string{
		{"event", "watch", "--limit", "20000"},
		{"signal", "watch", "--limit", "20000"},
	} {
		if !isStreamingWatchCommand(args) {
			t.Fatalf("watch command should stream: %v", args)
		}
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

type fakeAgentControlServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	applyReq        *controlplanev1.ApplyPolicyRequest
	contentReq      *controlplanev1.ApplyContentRequest
	getEventReq     *controlplanev1.GetEventRequest
	debugProfileReq *controlplanev1.DebugProfileRequest
	watchEventReq   *controlplanev1.WatchEventsRequest
	watchSignalReq  *controlplanev1.WatchSignalsRequest
	enrollReq       *controlplanev1.EnrollRequest
	unenrollReq     *controlplanev1.UnenrollRequest
	enrollStatus    string
	healthModes     []string
	healthCalls     int
}

func (s *fakeAgentControlServer) Enroll(ctx context.Context, req *controlplanev1.EnrollRequest) (*controlplanev1.ControlAck, error) {
	s.enrollReq = req
	status := s.enrollStatus
	if status == "" {
		status = "applied"
	}
	return &controlplanev1.ControlAck{Status: status, AgentId: req.GetAgentId(), TenantId: req.GetTenantId(), Message: "waiting for manager endpoint policy"}, nil
}

func (s *fakeAgentControlServer) Health(context.Context, *controlplanev1.HealthRequest) (*controlplanev1.HealthResponse, error) {
	mode := "standalone"
	if len(s.healthModes) > 0 {
		index := s.healthCalls
		if index >= len(s.healthModes) {
			index = len(s.healthModes) - 1
		}
		mode = s.healthModes[index]
	}
	s.healthCalls++
	return &controlplanev1.HealthResponse{AgentId: "agent-a", TenantId: "default", LocalStore: &controlplanev1.LocalStoreHealth{Mode: mode}}, nil
}

func (s *fakeAgentControlServer) Unenroll(ctx context.Context, req *controlplanev1.UnenrollRequest) (*controlplanev1.ControlAck, error) {
	s.unenrollReq = req
	return &controlplanev1.ControlAck{Status: "applied"}, nil
}

func (fakeAgentControlServer) Capability(ctx context.Context, req *controlplanev1.CapabilityRequest) (*controlplanev1.CapabilityResponse, error) {
	return &controlplanev1.CapabilityResponse{
		AgentId:  req.GetContext().GetAgentId(),
		TenantId: req.GetContext().GetTenantId(),
		Sensor:   &controlplanev1.SensorCapability{Backend: "fake", SupportsExec: true},
	}, nil
}

func (s *fakeAgentControlServer) ApplyPolicy(ctx context.Context, req *controlplanev1.ApplyPolicyRequest) (*controlplanev1.ControlAck, error) {
	s.applyReq = req
	return &controlplanev1.ControlAck{
		RequestId:     req.GetContext().GetRequestId(),
		TenantId:      req.GetContext().GetTenantId(),
		AgentId:       req.GetContext().GetAgentId(),
		Status:        "validated",
		PolicyId:      "local",
		PolicyVersion: 2,
	}, nil
}

func (s *fakeAgentControlServer) ApplyContent(ctx context.Context, req *controlplanev1.ApplyContentRequest) (*controlplanev1.ControlAck, error) {
	s.contentReq = req
	return &controlplanev1.ControlAck{
		RequestId: req.GetContext().GetRequestId(),
		TenantId:  req.GetContext().GetTenantId(),
		AgentId:   req.GetContext().GetAgentId(),
		Status:    "applied",
		Message:   "content applied",
	}, nil
}

func (s *fakeAgentControlServer) ListContent(ctx context.Context, req *controlplanev1.ListContentRequest) (*controlplanev1.ListContentResponse, error) {
	return &controlplanev1.ListContentResponse{Records: []*controlplanev1.ContentRecord{{
		Ref:     "ioc:c2-ip-feed",
		Kind:    "iocpack",
		Version: "2026.06.17.1",
	}}}, nil
}

func (s *fakeAgentControlServer) GetContent(ctx context.Context, req *controlplanev1.GetContentRequest) (*controlplanev1.ContentGetResponse, error) {
	return &controlplanev1.ContentGetResponse{Record: &controlplanev1.ContentRecord{
		Ref:     req.GetRef(),
		Kind:    "iocpack",
		Version: "2026.06.17.1",
	}}, nil
}

func (s *fakeAgentControlServer) GetEvent(ctx context.Context, req *controlplanev1.GetEventRequest) (*controlplanev1.EventGetResponse, error) {
	s.getEventReq = req
	return &controlplanev1.EventGetResponse{Frame: &controlplanev1.EventFrame{
		TenantId: "default",
		AgentId:  "agent-a",
		Sequence: 1,
		Event: &eventv1.CanonicalEvent{
			Id:       req.GetEventId(),
			Behavior: "process.exec",
		},
	}}, nil
}

func (s *fakeAgentControlServer) DebugProfile(ctx context.Context, req *controlplanev1.DebugProfileRequest) (*controlplanev1.DebugProfileResponse, error) {
	s.debugProfileReq = req
	return &controlplanev1.DebugProfileResponse{
		ProfileType: req.GetProfileType(),
		Seconds:     req.GetSeconds(),
		StartedAt:   "2026-06-29T00:00:00Z",
		FinishedAt:  "2026-06-29T00:00:01Z",
		Profile:     []byte("fake-profile"),
		Label:       req.GetLabel(),
	}, nil
}

func (s *fakeAgentControlServer) WatchEvents(req *controlplanev1.WatchEventsRequest, stream controlplanev1.AgentControlPlaneService_WatchEventsServer) error {
	s.watchEventReq = req
	return stream.Send(&controlplanev1.EventFrame{
		TenantId: "default",
		AgentId:  "agent-a",
		Sequence: 1,
		Event: &eventv1.CanonicalEvent{
			Id:       "ev-a",
			Behavior: "process.exec",
		},
	})
}

func (s *fakeAgentControlServer) WatchSignals(req *controlplanev1.WatchSignalsRequest, stream controlplanev1.AgentControlPlaneService_WatchSignalsServer) error {
	s.watchSignalReq = req
	return stream.Send(&controlplanev1.SignalFrame{
		TenantId: "default",
		AgentId:  "agent-a",
		Sequence: 1,
		Signal: &signalv1.Signal{
			Id:        "sig-a",
			Name:      "payload_dropped",
			Where:     signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
			EventRefs: []string{"ev-a"},
		},
	})
}

type blockingAgentControlServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
}

func (s *blockingAgentControlServer) WatchSignals(req *controlplanev1.WatchSignalsRequest, stream controlplanev1.AgentControlPlaneService_WatchSignalsServer) error {
	if err := stream.Send(&controlplanev1.SignalFrame{
		TenantId: "default",
		AgentId:  "agent-a",
		Sequence: 1,
		Signal: &signalv1.Signal{
			Id:    "sig-a",
			Name:  "payload_dropped",
			Where: signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT,
		},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
