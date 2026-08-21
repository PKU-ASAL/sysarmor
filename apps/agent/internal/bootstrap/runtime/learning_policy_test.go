package runtime

import (
	"strings"
	"testing"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	policymodel "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
	domainprocess "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/process"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

func TestValidateLearningPolicyRequiresMatchingLoadedModel(t *testing.T) {
	want := &policymodel.LearningModelRef{Ref: "model:a", Version: "2", Digest: "sha256:abc"}
	if err := validateLearningPolicy(want, nil); err == nil || !strings.Contains(err.Error(), "not loaded") {
		t.Fatalf("missing model error = %v", err)
	}
	detector := &identifiedProfileDetector{identity: ports.ProfileDetectorIdentity{
		Ref: "model:a", Version: "2", Digest: "sha256:different",
	}}
	if err := validateLearningPolicy(want, detector); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched model error = %v", err)
	}
	detector.identity.Digest = "sha256:abc"
	if err := validateLearningPolicy(want, detector); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyProfileDetectorRunsOnlyForDeclaredModel(t *testing.T) {
	delegate := &identifiedProfileDetector{
		identity: ports.ProfileDetectorIdentity{Ref: "model:a", Version: "2", Digest: "sha256:abc"},
		signals:  []*domaindetection.Signal{{ID: "candidate-a"}},
	}
	policy := &policyRuntime{}
	detector := &policyProfileDetector{policy: policy, delegate: delegate}

	if signals := detector.Process(domainprocess.Snapshot{}); len(signals) != 0 || delegate.calls != 0 {
		t.Fatalf("rule-only signals = %v calls = %d", signals, delegate.calls)
	}
	policy.setEndpointPolicy(policymodel.EndpointPolicy{Detection: policymodel.DetectionPolicy{
		LearningModel: &policymodel.LearningModelRef{Ref: "model:a", Version: "2", Digest: "sha256:abc"},
	}})
	if signals := detector.Process(domainprocess.Snapshot{}); len(signals) != 1 || delegate.calls != 1 {
		t.Fatalf("learning signals = %v calls = %d", signals, delegate.calls)
	}
}

type identifiedProfileDetector struct {
	identity ports.ProfileDetectorIdentity
	signals  []*domaindetection.Signal
	calls    int
}

func (detector *identifiedProfileDetector) Identity() ports.ProfileDetectorIdentity {
	return detector.identity
}

func (detector *identifiedProfileDetector) Process(domainprocess.Snapshot) []*domaindetection.Signal {
	detector.calls++
	return detector.signals
}
