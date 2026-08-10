package managerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestPolicyRolloutsDeriveAgentControlState(t *testing.T) {
	tests := []struct {
		name          string
		health        agenthealth.AgentHealth
		commandStatus string
		wantStatus    string
		wantDrift     bool
	}{
		{name: "applied", health: rolloutHealth("rollout-policy", 3, agenthealth.PendingPolicyStatus{}), commandStatus: controlmodel.ControlCommandStatusFailed, wantStatus: "applied"},
		{name: "pending health", health: rolloutHealth("old-policy", 1, agenthealth.PendingPolicyStatus{Status: "pending", Source: "managed", PolicyID: "rollout-policy", Version: 3, Digest: "sha256:pending"}), wantStatus: "pending", wantDrift: true},
		{name: "pending command", health: rolloutHealth("old-policy", 1, agenthealth.PendingPolicyStatus{}), commandStatus: controlmodel.ControlCommandStatusSent, wantStatus: "pending", wantDrift: true},
		{name: "failed", health: rolloutHealth("old-policy", 1, agenthealth.PendingPolicyStatus{}), commandStatus: controlmodel.ControlCommandStatusRejected, wantStatus: "failed", wantDrift: true},
		{name: "drifted", health: rolloutHealth("old-policy", 1, agenthealth.PendingPolicyStatus{}), commandStatus: controlmodel.ControlCommandStatusApplied, wantStatus: "drifted", wantDrift: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := rolloutStore(t, tt.health, tt.commandStatus)
			rec := get(t, rolloutServer(t, st, nil).Handler(), "/api/v1/policy-rollouts?tenant_id=default&agent_id=rollout-agent")
			if rec.Code != http.StatusOK {
				t.Fatalf("rollout status = %d body=%s", rec.Code, rec.Body.String())
			}
			var got []struct {
				Status               string                          `json:"status"`
				DesiredPolicyID      string                          `json:"desired_policy_id"`
				DesiredPolicyVersion uint64                          `json:"desired_policy_version"`
				AppliedPolicyID      string                          `json:"applied_policy_id"`
				PendingPolicy        agenthealth.PendingPolicyStatus `json:"pending_policy"`
				CommandStatus        string                          `json:"command_status"`
				Drift                bool                            `json:"drift"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode rollout: %v body=%s", err, rec.Body.String())
			}
			if len(got) != 1 || got[0].Status != tt.wantStatus || got[0].Drift != tt.wantDrift {
				t.Fatalf("rollouts = %+v, want status=%s drift=%t", got, tt.wantStatus, tt.wantDrift)
			}
			if got[0].DesiredPolicyID != "rollout-policy" || got[0].DesiredPolicyVersion != 3 || got[0].AppliedPolicyID != tt.health.PolicyID {
				t.Fatalf("rollout policy projection = %+v", got[0])
			}
			if got[0].PendingPolicy != tt.health.PendingPolicy || got[0].CommandStatus != tt.commandStatus {
				t.Fatalf("rollout evidence = %+v, health=%+v command=%q", got[0], tt.health, tt.commandStatus)
			}
		})
	}
}

func TestPolicyRolloutsWithoutHealthOrCommandAreUnknown(t *testing.T) {
	st := rolloutStore(t, agenthealth.AgentHealth{}, "")
	rec := get(t, rolloutServer(t, st, nil).Handler(), "/api/v1/policy-rollouts?agent_id=rollout-agent")
	var got []PolicyRollout
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode rollout: %v body=%s", err, rec.Body.String())
	}
	if len(got) != 1 || got[0].Status != "unknown" || got[0].Drift {
		t.Fatalf("rollouts = %+v, want unknown without drift", got)
	}
}

func TestPolicyRolloutsFilterByStatus(t *testing.T) {
	st := rolloutStore(t, rolloutHealth("old-policy", 1, agenthealth.PendingPolicyStatus{}), controlmodel.ControlCommandStatusSent)
	rec := get(t, rolloutServer(t, st, nil).Handler(), "/api/v1/policy-rollouts?status=applied")
	if rec.Code != http.StatusOK || rec.Body.String() != "[]\n" {
		t.Fatalf("filtered rollouts status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPolicyRolloutsReturnServerErrorWhenFactStoreFails(t *testing.T) {
	st := &store.Store{Agents: []store.AgentIdentity{{TenantID: "default", AgentID: "stale-agent"}}}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policy-rollouts", nil)
	rec := httptest.NewRecorder()
	server := newAdminTestServer(st)
	server.SetIdentityApplication(&rolloutIdentityQuery{err: context.Canceled}, PolicyRequestContext)
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("rollout backend failure status = %d body=%s", rec.Code, rec.Body.String())
	}
}

type rolloutIdentityQuery struct {
	agents []domainidentity.AgentView
	health map[domainidentity.AgentID]domainidentity.Health
	err    error
}

func (query *rolloutIdentityQuery) Rarity(context.Context, managerapp.RequestContext) (domainidentity.RarityBaseline, error) {
	return domainidentity.RarityBaseline{}, query.err
}
func (query *rolloutIdentityQuery) Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error) {
	return domainidentity.Metrics{}, query.err
}
func (query *rolloutIdentityQuery) AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	return domainidentity.AgentOverview{}, query.err
}

func (query *rolloutIdentityQuery) ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error) {
	return identityapp.ListAgentsResult{Agents: query.agents}, query.err
}

func (query *rolloutIdentityQuery) GetHealth(_ context.Context, _ managerapp.RequestContext, agentID domainidentity.AgentID) (domainidentity.Health, error) {
	if query.err != nil {
		return domainidentity.Health{}, query.err
	}
	value, ok := query.health[agentID]
	if !ok {
		return domainidentity.Health{}, failure.New(failure.NotFound, "health not found")
	}
	return value, nil
}

func rolloutServer(t *testing.T, st *store.Store, queryErr error) *Server {
	t.Helper()
	tenantID, err := tenant.NewID("default")
	if err != nil {
		t.Fatal(err)
	}
	query := &rolloutIdentityQuery{err: queryErr, health: map[domainidentity.AgentID]domainidentity.Health{}}
	for _, agent := range st.Agents {
		query.agents = append(query.agents, domainidentity.AgentView{Agent: domainidentity.Agent{TenantID: tenantID, ID: domainidentity.AgentID(agent.AgentID)}})
	}
	for _, health := range st.Health {
		document, err := json.Marshal(health)
		if err != nil {
			t.Fatal(err)
		}
		query.health[domainidentity.AgentID(health.AgentID)] = domainidentity.Health{TenantID: tenantID, AgentID: domainidentity.AgentID(health.AgentID), Document: document}
	}
	server := NewServer(st)
	server.SetIdentityApplication(query, PolicyRequestContext)
	commands := make([]domaincontrol.Command, 0, len(st.ControlCommands))
	for _, value := range st.ControlCommands {
		commands = append(commands, domaincontrol.Command{
			ID: value.CommandID, TenantID: tenantID, AgentID: value.AgentID,
			Type: domaincontrol.CommandType(value.Type), Status: domaincontrol.CommandStatus(value.Status),
			PolicyID: value.PolicyID, PolicyVersion: value.PolicyVersion, CreatedAt: value.CreatedAt,
			UpdatedAt: value.UpdatedAt, LastSentAt: value.LastSentAt, AckedAt: value.AckedAt,
			AttemptCount: value.AttemptCount, Error: value.Error, AckMessage: value.AckMessage,
		})
	}
	server.SetControlApplication(rolloutControlQuery{commands: commands})
	return server
}

type rolloutControlQuery struct{ commands []domaincontrol.Command }

func (query rolloutControlQuery) Commands(context.Context, managerapp.RequestContext, controlapp.CommandQuery) ([]domaincontrol.Command, error) {
	return query.commands, nil
}

func rolloutStore(t *testing.T, health agenthealth.AgentHealth, commandStatus string) *store.Store {
	t.Helper()
	st := &store.Store{}
	policy := policymodel.DefaultPolicy("default")
	policy.PolicyID, policy.Version, policy.Published = "rollout-policy", 3, true
	st.UpsertPolicy(policy)
	if _, ok, err := st.AssignPolicy(policymodel.Assignment{TenantID: "default", AgentID: "rollout-agent", PolicyID: policy.PolicyID, PolicyVersion: policy.Version}); err != nil || !ok {
		t.Fatalf("assign rollout policy ok=%t err=%v", ok, err)
	}
	if health.AgentID != "" {
		st.UpsertAgentHealth(health)
	}
	if commandStatus != "" {
		if _, err := st.CreateControlCommand(controlmodel.ControlCommand{
			CommandID: "rollout-command", TenantID: "default", AgentID: "rollout-agent",
			Type: controlmodel.ControlCommandTypePolicyUpdate, Status: commandStatus,
			PolicyID: policy.PolicyID, PolicyVersion: policy.Version, AttemptCount: 2,
			LastSentAt: time.Date(2026, 8, 3, 1, 2, 3, 0, time.UTC),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func rolloutHealth(policyID string, version uint64, pending agenthealth.PendingPolicyStatus) agenthealth.AgentHealth {
	return agenthealth.AgentHealth{
		TenantID: "default", AgentID: "rollout-agent", HostID: "rollout-host",
		Status: "ok", PolicyID: policyID, PolicyVersion: version, PendingPolicy: pending,
		ObservedAt: time.Date(2026, 8, 3, 1, 3, 0, 0, time.UTC),
	}
}
