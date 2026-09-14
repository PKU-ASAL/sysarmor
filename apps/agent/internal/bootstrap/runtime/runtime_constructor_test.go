package runtime

import (
	"errors"
	"strings"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/fake"
)

func TestNewCoordinatorTracksLearningDetectorState(t *testing.T) {
	detector := &learningDetectorStub{}
	base := Dependencies{Sensor: fake.New(), Content: agentcontent.NewStore(), Policy: newTestPolicyController}
	loaded := base
	loaded.LearningDetector = detector
	coordinator, err := NewCoordinator(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.learningDetector != detector || coordinator.healthRuntime().detectionHealth().Learning.Status != "loaded" {
		t.Fatalf("loaded learning state = %+v", coordinator.healthRuntime().detectionHealth().Learning)
	}

	degraded := base
	degraded.LearningError = errors.New("invalid model bundle")
	coordinator, err = NewCoordinator(degraded)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}
	learning := coordinator.healthRuntime().detectionHealth().Learning
	if coordinator.learningDetector != nil || learning.Status != "degraded" || learning.LastError != "invalid model bundle" {
		t.Fatalf("degraded learning state = %+v", learning)
	}
}

func TestNewCoordinatorRejectsMissingCompositionDependencies(t *testing.T) {
	tests := []struct {
		name         string
		dependencies Dependencies
		want         string
	}{
		{name: "sensor", dependencies: Dependencies{}, want: "sensor"},
		{name: "content", dependencies: Dependencies{Sensor: fake.New()}, want: "content"},
		{name: "policy", dependencies: Dependencies{Sensor: fake.New(), Content: agentcontent.NewStore()}, want: "policy controller"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCoordinator(test.dependencies)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewCoordinator() error = %v, want missing %s error", err, test.want)
			}
		})
	}
}
