package policy

import (
	"context"
	"sort"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	domaincontrol "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/control"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type RolloutIdentityQueries interface {
	ListAgents(context.Context, managerapp.RequestContext, identityapp.ListAgentsQuery) (identityapp.ListAgentsResult, error)
	ListHealth(context.Context, managerapp.RequestContext, identityapp.ListHealthQuery) (identityapp.ListHealthResult, error)
}

type RolloutPolicyQueries interface {
	ListAssignments(context.Context, managerapp.RequestContext, domainpolicy.AssignmentFilter) ([]domainpolicy.Assignment, error)
	ListPolicies(context.Context, managerapp.RequestContext, ListPoliciesQuery) (ListPoliciesResult, error)
}

type RolloutControlQueries interface {
	Commands(context.Context, managerapp.RequestContext, controlapp.CommandQuery) ([]domaincontrol.Command, error)
}

type RolloutService struct {
	identity RolloutIdentityQueries
	policies RolloutPolicyQueries
	controls RolloutControlQueries
}

func NewRolloutService(identity RolloutIdentityQueries, policies RolloutPolicyQueries, controls RolloutControlQueries) *RolloutService {
	return &RolloutService{identity: identity, policies: policies, controls: controls}
}

type RolloutQuery struct{ AgentID, Status string }

type Rollout struct {
	TenantID                                    tenant.ID
	AgentID, Status                             string
	DesiredPolicyID, AppliedPolicyID            string
	DesiredPolicyVersion, AppliedPolicyVersion  uint64
	PendingPolicy                               domainidentity.PendingPolicy
	CommandID, CommandStatus, Error             string
	LastDispatchAt, LastAckAt, HealthObservedAt time.Time
	AttemptCount                                uint32
	Drift                                       bool
}

type rolloutFacts struct {
	targets         []string
	healthByAgent   map[string]domainidentity.Health
	assignments     []domainpolicy.Assignment
	policies        []domainpolicy.Policy
	commandsByAgent map[string][]domaincontrol.Command
}

func (service *RolloutService) List(ctx context.Context, request managerapp.RequestContext, query RolloutQuery) ([]Rollout, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return nil, err
	}
	facts, err := service.loadFacts(ctx, request, query.AgentID)
	if err != nil {
		return nil, err
	}
	result := make([]Rollout, 0, len(facts.targets))
	for _, agentID := range facts.targets {
		value := projectRollout(request.Actor.TenantID, agentID, facts)
		if query.Status == "" || value.Status == query.Status {
			result = append(result, value)
		}
	}
	return result, nil
}

func (service *RolloutService) loadFacts(ctx context.Context, request managerapp.RequestContext, agentID string) (rolloutFacts, error) {
	agents, err := service.identity.ListAgents(ctx, request, identityapp.ListAgentsQuery{})
	if err != nil {
		return rolloutFacts{}, err
	}
	health, err := service.identity.ListHealth(ctx, request, identityapp.ListHealthQuery{Filter: domainidentity.HealthFilter{AgentID: agentID}})
	if err != nil {
		return rolloutFacts{}, err
	}
	assignments, err := service.policies.ListAssignments(ctx, request, domainpolicy.AssignmentFilter{})
	if err != nil {
		return rolloutFacts{}, err
	}
	policies, err := service.policies.ListPolicies(ctx, request, ListPoliciesQuery{})
	if err != nil {
		return rolloutFacts{}, err
	}
	commands, err := service.controls.Commands(ctx, request, controlapp.CommandQuery{AgentID: agentID, Type: domaincontrol.CommandTypePolicyUpdate})
	if err != nil {
		return rolloutFacts{}, err
	}
	return buildRolloutFacts(request.Actor.TenantID, agentID, agents.Agents, health.Health, assignments, policies.Policies, commands), nil
}

func buildRolloutFacts(authenticated tenant.ID, filter string, agents []domainidentity.AgentView, health []domainidentity.Health,
	assignments []domainpolicy.Assignment, policies []domainpolicy.Policy, commands []domaincontrol.Command) rolloutFacts {
	seen := map[string]struct{}{}
	for _, view := range agents {
		addRolloutAgent(seen, authenticated, view.Agent.TenantID, string(view.Agent.ID), filter)
	}
	for _, assignment := range assignments {
		addRolloutAgent(seen, authenticated, assignment.TenantID, assignment.Target.AgentID, filter)
	}
	targets := make([]string, 0, len(seen))
	for id := range seen {
		targets = append(targets, id)
	}
	sort.Strings(targets)
	facts := rolloutFacts{targets: targets, assignments: assignments, policies: policies,
		healthByAgent: map[string]domainidentity.Health{}, commandsByAgent: map[string][]domaincontrol.Command{}}
	for _, value := range health {
		if value.TenantID == authenticated {
			facts.healthByAgent[string(value.AgentID)] = value
		}
	}
	for _, value := range commands {
		if value.TenantID == authenticated && value.AgentID != "" {
			facts.commandsByAgent[value.AgentID] = append(facts.commandsByAgent[value.AgentID], value)
		}
	}
	return facts
}

func addRolloutAgent(seen map[string]struct{}, authenticated, candidate tenant.ID, value, filter string) {
	if value != "" && candidate == authenticated && (filter == "" || value == filter) {
		seen[value] = struct{}{}
	}
}
