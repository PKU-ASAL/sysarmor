package managerapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestPolicyAPIAssignmentAndCloudRuleDisable(t *testing.T) {
	st := &store.Store{}
	srv := NewServer(st)
	handler := adminTestHandler(srv)

	rec := get(t, handler, "/api/v1/policies?tenant_id=default")
	if !strings.Contains(rec.Body.String(), policymodel.DefaultPolicyID) {
		t.Fatalf("policies response missing default policy: %s", rec.Body.String())
	}

	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "no-cross-incident"
	policy.Version = 1
	policy.CloudRules = []string{"web_shell_chain"}
	policyData, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies?actor=tester&reason=draft", strings.NewReader(string(policyData)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy post status = %d body=%s", rec.Code, rec.Body.String())
	}

	assignment := policymodel.Assignment{
		TenantID: "default",
		AgentID:  "agent-policy",
		PolicyID: "no-cross-incident",
	}
	assignmentData, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(string(assignmentData)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("assignment post status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/effective-policy?tenant_id=default&agent_id=agent-policy")
	if !strings.Contains(rec.Body.String(), `"policy_id":"no-cross-incident"`) || strings.Contains(rec.Body.String(), "dropped_payload_executed_and_connects") {
		t.Fatalf("effective policy response = %s", rec.Body.String())
	}

	appendBatch(t, srv, httpDataBatch("", "agent-policy", "host-a", nil, []*signalv1.Signal{
		endpointSignalForScenario("apt-staged-drop-policy", "payload_dropped", "lin-drop", false, fileEntity("/var/lib/app/plugins/helper")),
		endpointSignalForScenario("apt-staged-drop-policy", "suspicious_exec_connect", "lin-connect", false, fileEntity("/var/lib/app/plugins/helper"), socketEntity("10.66.0.99:443")),
	}))
	rec = get(t, handler, "/api/v1/signals?label=scenario=apt-staged-drop-policy&layer=cloud")
	if strings.Contains(rec.Body.String(), "dropped_payload_executed_and_connects") {
		t.Fatalf("disabled cloud rule still emitted signal: %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/incidents?label=scenario=apt-staged-drop-policy")
	if strings.Contains(rec.Body.String(), `"inc-`) {
		t.Fatalf("disabled cloud rule still created incident: %s", rec.Body.String())
	}
}

func TestPolicyAPIDraftRequiresPublishBeforeAssignment(t *testing.T) {
	st := &store.Store{}
	handler := newAdminTestServer(st).Handler()
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "draft-policy"
	policy.Version = 2
	policy.Published = false
	policyData, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies?actor=tester&reason=draft", strings.NewReader(string(policyData)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy post status = %d body=%s", rec.Code, rec.Body.String())
	}
	assignmentData := `{"tenant_id":"default","agent_id":"agent-draft","policy_id":"draft-policy","policy_version":2,"actor":"operator","reason":"deploy"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(assignmentData))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("draft assignment status = %d body=%s", rec.Code, rec.Body.String())
	}
	publish := `{"tenant_id":"default","policy_id":"draft-policy","version":2,"published":true,"actor":"reviewer","reason":"ready"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-publish", strings.NewReader(publish))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"published":true`) {
		t.Fatalf("publish status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(assignmentData))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("published assignment status = %d body=%s", rec.Code, rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/effective-policy?tenant_id=default&agent_id=agent-draft")
	if !strings.Contains(rec.Body.String(), `"policy_id":"draft-policy"`) || !strings.Contains(rec.Body.String(), `"published":true`) {
		t.Fatalf("effective policy response = %s", rec.Body.String())
	}
	rec = get(t, handler, "/api/v1/policy-audit?tenant_id=default&policy_id=draft-policy")
	for _, want := range []string{`"action":"policy.upsert"`, `"action":"policy.publish"`, `"action":"policy.assign"`, `"actor":"test-admin"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("policy audit missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestPrincipalGuardsControlPlaneWritesAndAuditActor(t *testing.T) {
	st := &store.Store{}
	handler := NewServer(st).Handler()
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "guarded-policy"
	policy.Version = 3
	policy.Published = false
	policyData, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies?reason=header-actor", strings.NewReader(string(policyData)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("policy write without principal status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/policies?reason=header-actor", strings.NewReader(string(policyData)))
	req = withTestPrincipal(req, "operator", "default", "operator")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("policy write with operator status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/policies?reason=header-actor", strings.NewReader(string(policyData)))
	req = withTestPrincipal(req, "jwt-admin", "default", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy write with admin principal status = %d body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/policy-audit?tenant_id=default&policy_id=guarded-policy", nil)
	req = withTestPrincipal(req, "jwt-admin", "default", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	for _, want := range []string{`"action":"policy.upsert"`, `"actor":"jwt-admin"`, `"reason":"header-actor"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("policy audit missing %s: %s", want, rec.Body.String())
		}
	}
}

func TestPolicyAssignmentDownlinkCreatesPolicyUpdateCommand(t *testing.T) {
	st := &store.Store{}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "downlink-policy"
	policy.Version = 7
	policy.Published = true
	st.UpsertPolicy(policy)
	handler := newAdminTestServer(st).Handler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(`{
		"tenant_id":"default",
		"agent_id":"agent-downlink",
		"policy_id":"downlink-policy",
		"policy_version":7,
		"downlink":true,
		"command_id":"ctrl-policy-downlink",
		"actor":"policy-operator",
		"reason":"deploy immediately"
	}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("assignment downlink status = %d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{`"assignment"`, `"control_command"`, `"command_id":"ctrl-policy-downlink"`, `"type":"policy_update"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("assignment downlink response missing %s: %s", want, rec.Body.String())
		}
	}
	commands := st.PendingControlCommands("default", "agent-downlink")
	if len(commands) != 1 || commands[0].CommandID != "ctrl-policy-downlink" || commands[0].PolicyID != "downlink-policy" || commands[0].PolicyVersion != 7 || commands[0].Actor != "test-admin" {
		t.Fatalf("pending commands = %+v", commands)
	}
}

func TestPolicyAssignmentDownlinkRequiresControlAdmin(t *testing.T) {
	st := &store.Store{}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID = "downlink-auth-policy"
	policy.Version = 1
	policy.Published = true
	st.UpsertPolicy(policy)
	handler := NewServer(st).Handler()

	body := `{"tenant_id":"default","agent_id":"agent-a","policy_id":"downlink-auth-policy","policy_version":1,"downlink":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(body))
	req = withTestPrincipal(req, "operator", "default", "operator")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("downlink with policy_admin only status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/policy-assignments", strings.NewReader(body))
	req = withTestPrincipal(req, "admin", "default", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"control_command"`) {
		t.Fatalf("downlink with control_admin status = %d body=%s", rec.Code, rec.Body.String())
	}
}
