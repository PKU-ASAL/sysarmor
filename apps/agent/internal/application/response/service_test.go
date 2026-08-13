package response

import (
	"context"
	"errors"
	"testing"

	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type recordingRuntime struct {
	identity ports.ResponseIdentity
	policy   domainresponse.Policy
	ack      ports.ResponseExecutionAck
	err      error
	command  ports.ResponseExecution
}

func (r *recordingRuntime) Identity() ports.ResponseIdentity { return r.identity }
func (r *recordingRuntime) Policy() domainresponse.Policy    { return r.policy }
func (r *recordingRuntime) Scope() (domainresponse.Scope, bool) {
	return domainresponse.Scope{}, false
}
func (r *recordingRuntime) Enforce(_ context.Context, command ports.ResponseExecution) (ports.ResponseExecutionAck, error) {
	r.command = command
	return r.ack, r.err
}

func TestServiceRejectsUnauthorizedDestructiveEnforcementBeforePort(t *testing.T) {
	runtime := &recordingRuntime{identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", Mode: domainresponse.ModeEnforce, Action: "kill", Target: "process:42",
	})
	if ack.Accepted || !ack.Unsupported || runtime.command.ID != "" {
		t.Fatalf("ack=%+v command=%+v", ack, runtime.command)
	}
}

func TestServiceRejectsMismatchedCommandBindingsBeforePort(t *testing.T) {
	tests := []struct {
		name    string
		command domainresponse.Command
	}{
		{name: "tenant", command: domainresponse.Command{TenantID: "tenant-b"}},
		{name: "agent", command: domainresponse.Command{AgentID: "agent-b"}},
		{name: "policy id", command: domainresponse.Command{PolicyID: "policy-b"}},
		{name: "policy version", command: domainresponse.Command{PolicyVersion: 8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &recordingRuntime{
				identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
				policy: domainresponse.Policy{
					ID: "policy-a", Version: 7, AllowedActions: []string{"noop"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce},
				},
			}
			command := tt.command
			command.ID, command.Action, command.Mode = "response-a", "noop", domainresponse.ModeEnforce
			ack := NewService(runtime, runtime).Execute(t.Context(), command)
			if ack.Accepted || !ack.Unsupported || runtime.command.ID != "" {
				t.Fatalf("ack=%+v execution=%+v", ack, runtime.command)
			}
		})
	}
}

func TestServiceRejectsMissingCommandBindingsBeforePort(t *testing.T) {
	base := domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a",
		PolicyID: "policy-a", PolicyVersion: 7, Action: "noop", Mode: domainresponse.ModeEnforce,
	}
	tests := []struct {
		name  string
		clear func(*domainresponse.Command)
	}{
		{name: "tenant", clear: func(command *domainresponse.Command) { command.TenantID = "" }},
		{name: "agent", clear: func(command *domainresponse.Command) { command.AgentID = "" }},
		{name: "policy id", clear: func(command *domainresponse.Command) { command.PolicyID = "" }},
		{name: "policy version", clear: func(command *domainresponse.Command) { command.PolicyVersion = 0 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := boundRuntime()
			command := base
			tt.clear(&command)
			ack := NewService(runtime, runtime).Execute(t.Context(), command)
			if ack.Accepted || !ack.Unsupported || runtime.command.ID != "" {
				t.Fatalf("ack=%+v execution=%+v", ack, runtime.command)
			}
		})
	}
}

func boundRuntime() *recordingRuntime {
	return &recordingRuntime{
		identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		policy: domainresponse.Policy{
			ID: "policy-a", Version: 7, AllowedActions: []string{"noop"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce},
		},
	}
}

func TestServiceRejectsUnauthorizedObserveBeforeAccepting(t *testing.T) {
	runtime := &recordingRuntime{identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", Mode: domainresponse.ModeObserve, Action: "kill",
	})
	if ack.Accepted || ack.ObserveOnly || !ack.Unsupported || runtime.command.ID != "" {
		t.Fatalf("ack=%+v execution=%+v", ack, runtime.command)
	}
}

func TestServiceObserveModeBindsEndpointIdentity(t *testing.T) {
	runtime := &recordingRuntime{
		identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		policy:   domainresponse.Policy{ID: "policy-a", Version: 7},
	}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 7,
		Action: "collect", Target: "process:42",
	})
	if !ack.Accepted || !ack.ObserveOnly || ack.Executed || ack.TenantID != "tenant-a" || ack.AgentID != "agent-a" {
		t.Fatalf("ack=%+v", ack)
	}
	if runtime.command.ID != "" {
		t.Fatalf("observe response reached enforcement runtime: %+v", runtime.command)
	}
}

func TestServiceEnforcementFailureIsUnsupported(t *testing.T) {
	runtime := &recordingRuntime{
		identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		policy: domainresponse.Policy{
			ID: "policy-a", Version: 7, AllowedActions: []string{"kill"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce}, AllowDestructive: true,
		},
		err: errors.New("sensor unavailable"),
	}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 7,
		Mode: domainresponse.ModeEnforce, Action: "kill", Target: "process:42",
	})
	if ack.Accepted || !ack.Unsupported || ack.Executed || ack.TenantID != "tenant-a" || ack.AgentID != "agent-a" {
		t.Fatalf("ack=%+v", ack)
	}
	if runtime.command.ID != "response-a" || runtime.command.Action != "kill" {
		t.Fatalf("command=%+v", runtime.command)
	}
}

func TestServiceKeepsCommandIDWhenExecutorAckOmitsIt(t *testing.T) {
	runtime := &recordingRuntime{
		identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		policy: domainresponse.Policy{
			ID: "policy-a", Version: 7, AllowedActions: []string{"noop"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce},
		},
		ack: ports.ResponseExecutionAck{Accepted: true},
	}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 7,
		Mode: domainresponse.ModeEnforce, Action: "noop",
	})
	if ack.ResponseID != "response-a" || !ack.Executed {
		t.Fatalf("ack=%+v", ack)
	}
}

func TestServiceDoesNotReportObserveOnlyExecutorAckAsExecuted(t *testing.T) {
	runtime := &recordingRuntime{
		identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		policy: domainresponse.Policy{
			ID: "policy-a", Version: 7, AllowedActions: []string{"noop"}, AllowedModes: []domainresponse.Mode{domainresponse.ModeEnforce},
		},
		ack: ports.ResponseExecutionAck{Accepted: true, ObserveOnly: true},
	}
	ack := NewService(runtime, runtime).Execute(t.Context(), domainresponse.Command{
		ID: "response-a", TenantID: "tenant-a", AgentID: "agent-a", PolicyID: "policy-a", PolicyVersion: 7,
		Mode: domainresponse.ModeEnforce, Action: "noop",
	})
	if !ack.Accepted || !ack.ObserveOnly || ack.Executed {
		t.Fatalf("ack=%+v", ack)
	}
}

func TestServiceCollectEvidenceBuildsDomainSubgraph(t *testing.T) {
	runtime := &recordingRuntime{identity: ports.ResponseIdentity{TenantID: "tenant-a", AgentID: "agent-a"}}
	result := NewService(runtime, runtime).CollectEvidence(t.Context(), EvidenceRequest{RequestID: "request-a", Target: "process:42"})
	if !result.OK || result.TenantID != "tenant-a" || len(result.Evidence.Nodes) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if node := result.Evidence.Nodes[0]; node.Kind != "process" || node.ID != "process:42" {
		t.Fatalf("node=%+v", node)
	}
}
