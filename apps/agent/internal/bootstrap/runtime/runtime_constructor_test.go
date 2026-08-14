package runtime

import (
	"strings"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/fake"
)

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
