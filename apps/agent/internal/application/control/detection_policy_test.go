package control

import (
	"context"
	"testing"

	applicationpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/policy"
)

type detectionApplicationFake struct {
	candidate                      applicationpolicy.DetectionCandidate
	validated, activated, mutation bool
}

func (*detectionApplicationFake) PolicyIdentity() PolicyIdentity {
	return PolicyIdentity{TenantID: "tenant-a", AgentID: "agent-a"}
}
func (*detectionApplicationFake) ValidatePolicyContext(RequestContext) error { return nil }
func (f *detectionApplicationFake) BeginLocalPolicyMutation(_ context.Context, mutation bool) (func(), error) {
	f.mutation = mutation
	return func() {}, nil
}
func (f *detectionApplicationFake) ValidateDetection(context.Context, string) (applicationpolicy.DetectionCandidate, error) {
	f.validated = true
	return f.candidate, nil
}
func (f *detectionApplicationFake) ActivateDetection(context.Context, string) (applicationpolicy.DetectionResult, error) {
	f.activated = true
	return applicationpolicy.DetectionResult{Candidate: f.candidate, Report: f.candidate.BuildReport()}, nil
}

type controlDetectionCandidate struct{ status string }

func (controlDetectionCandidate) PolicyID() string      { return "detection-a" }
func (controlDetectionCandidate) PolicyVersion() uint64 { return 2 }
func (c controlDetectionCandidate) BuildReport() applicationpolicy.DetectionReport {
	return applicationpolicy.DetectionReport{Status: c.status, Message: "detection policy applied", ReportJSON: `{}`}
}

func TestDetectionControlDelegatesActivation(t *testing.T) {
	application := &detectionApplicationFake{candidate: controlDetectionCandidate{status: "applied"}}
	result := NewDetectionPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}"})
	if !application.activated || !application.mutation || result.Status != "applied" || result.PolicyID != "detection-a" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}

func TestDetectionControlDryRunOnlyValidates(t *testing.T) {
	application := &detectionApplicationFake{candidate: controlDetectionCandidate{status: "degraded"}}
	result := NewDetectionPolicyController(application).Apply(t.Context(), PolicyCommand{Document: "{}", DryRun: true})
	if !application.validated || application.activated || application.mutation || result.Status != "degraded" {
		t.Fatalf("result=%+v application=%+v", result, application)
	}
}
