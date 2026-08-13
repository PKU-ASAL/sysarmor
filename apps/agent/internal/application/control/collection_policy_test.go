package control

import (
	"context"
	"testing"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type collectionApplicationFake struct {
	validated, activated bool
	mutation             bool
	scope                applicationpolicy.CollectionScope
	candidate            applicationpolicy.CollectionCandidate
}

func (*collectionApplicationFake) PolicyIdentity() PolicyIdentity {
	return PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"}
}
func (*collectionApplicationFake) ValidatePolicyContext(RequestContext) error { return nil }
func (f *collectionApplicationFake) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	f.mutation = mutation
	return func() {}, nil
}
func (f *collectionApplicationFake) ValidateCollection(_ context.Context, _ string, scope applicationpolicy.CollectionScope) (applicationpolicy.CollectionCandidate, error) {
	f.validated = true
	f.scope = scope
	return f.candidate, nil
}
func (f *collectionApplicationFake) ActivateCollection(_ context.Context, _ string, scope applicationpolicy.CollectionScope) (applicationpolicy.CollectionResult, error) {
	f.activated = true
	f.scope = scope
	return applicationpolicy.CollectionResult{Candidate: f.candidate, Report: f.candidate.ValidationReport()}, nil
}

type controlCollectionCandidate struct{}

func (controlCollectionCandidate) PolicyID() string      { return "collection-a" }
func (controlCollectionCandidate) PolicyVersion() uint64 { return 2 }
func (controlCollectionCandidate) ValidationReport() applicationpolicy.CollectionReport {
	return applicationpolicy.CollectionReport{Status: "degraded", Message: "collection policy applied", ReportJSON: `{}`}
}

func TestCollectionControlDelegatesActivation(t *testing.T) {
	application := &collectionApplicationFake{candidate: controlCollectionCandidate{}}
	result := NewCollectionPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", Context: RequestContext{Scope: &Scope{Type: "container", Selector: "a"}}})
	if !application.activated || !application.mutation || application.scope.Type != "container" || result.Status != "degraded" || result.PolicyID != "collection-a" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}

func TestCollectionControlDryRunOnlyValidates(t *testing.T) {
	application := &collectionApplicationFake{candidate: controlCollectionCandidate{}}
	result := NewCollectionPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", DryRun: true})
	if !application.validated || application.activated || application.mutation || result.Status != "degraded" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}
