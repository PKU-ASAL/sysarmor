package control

import (
	"context"
	"errors"
	"testing"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type endpointApplicationFake struct {
	identity            PolicyIdentity
	validated, begun    bool
	standalone, managed bool
	candidate           applicationpolicy.EndpointCandidate
	report              applicationpolicy.EndpointReport
	pending             bool
	err                 error
}

func (f *endpointApplicationFake) PolicyIdentity() PolicyIdentity { return f.identity }
func (f *endpointApplicationFake) ValidatePolicyContext(RequestContext) error {
	f.validated = true
	return nil
}
func (f *endpointApplicationFake) BeginLocalPolicyMutation(context.Context, bool) (func(), error) {
	f.begun = true
	return func() {}, nil
}
func (f *endpointApplicationFake) ValidateEndpoint(context.Context, string, applicationpolicy.Source) (applicationpolicy.EndpointCandidate, error) {
	return f.candidate, f.err
}
func (f *endpointApplicationFake) ActivateStandaloneEndpoint(context.Context, string) (applicationpolicy.EndpointResult, error) {
	f.standalone = true
	return applicationpolicy.EndpointResult{Candidate: f.candidate, Report: f.report}, f.err
}
func (f *endpointApplicationFake) ActivateManagedEndpoint(context.Context, string) (applicationpolicy.EndpointResult, error) {
	f.managed = true
	return applicationpolicy.EndpointResult{Candidate: f.candidate, Report: f.report, Pending: f.pending}, f.err
}

type controlEndpointCandidate struct{ id string }

func (c controlEndpointCandidate) PolicyID() string    { return c.id }
func (controlEndpointCandidate) PolicyVersion() uint64 { return 3 }
func (controlEndpointCandidate) PolicySource() applicationpolicy.Source {
	return applicationpolicy.SourceStandalone
}

func TestEndpointControlDelegatesStandaloneActivation(t *testing.T) {
	application := &endpointApplicationFake{
		identity:  PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		candidate: controlEndpointCandidate{id: "endpoint-a"},
		report:    applicationpolicy.EndpointReport{Status: "applied"},
	}
	result := NewEndpointPolicyController(application).Apply(t.Context(), PolicyCommand{
		Context: RequestContext{RequestID: "request-a"}, Document: "{}", Source: PolicySourceStandalone,
	})
	if result.Status != "applied" || result.PolicyID != "endpoint-a" || !application.validated || !application.begun || !application.standalone || application.managed {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}

func TestEndpointControlMapsManagedPending(t *testing.T) {
	application := &endpointApplicationFake{
		candidate: controlEndpointCandidate{id: "endpoint-a"},
		report:    applicationpolicy.EndpointReport{Status: "pending", Message: "waiting for sensor recovery"},
		pending:   true,
	}
	result := NewEndpointPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", Source: PolicySourceManaged})
	if result.Status != "pending" || !result.RequiresRestart || !collectionSectionRequiresRestart(result) || !application.managed || application.begun {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}

func TestEndpointControlDryRunOnlyValidates(t *testing.T) {
	application := &endpointApplicationFake{candidate: controlEndpointCandidate{id: "endpoint-a"}}
	result := NewEndpointPolicyController(application).Apply(t.Context(), PolicyCommand{
		Document: "{}", Source: PolicySourceStandalone, DryRun: true,
	})
	if result.Status != "validated" || !result.RequiresRestart || !collectionSectionRequiresRestart(result) || application.standalone || application.managed {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}

func collectionSectionRequiresRestart(result Result) bool {
	for _, section := range result.Sections {
		if section.Name == "collection" {
			return section.RequiresRestart
		}
	}
	return false
}

func TestEndpointControlMapsApplicationFailure(t *testing.T) {
	application := &endpointApplicationFake{err: errors.New("invalid endpoint policy")}
	result := NewEndpointPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", Source: PolicySourceManaged})
	if result.Status != "rejected" || result.Message != "invalid endpoint policy" {
		t.Fatalf("result=%+v", result)
	}
}
