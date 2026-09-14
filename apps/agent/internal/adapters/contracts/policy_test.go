package contracts

import (
	"testing"

	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/policy"
)

func TestSensorCollectionIntentPreservesBoundaryFields(t *testing.T) {
	value := domainpolicy.CollectionIntent{
		Behaviors: []string{"process.exec"}, FilePrefixes: []string{"/tmp/"}, FileWriteExcludes: []string{"/run/sysarmor"},
		ScopeType: "container", ScopeSelector: "container-a", ObserveOnly: true,
	}

	got := SensorCollectionIntent(value)
	if len(got.Behaviors) != 1 || got.FilePrefixes[0] != "/tmp/" || got.FileWriteExcludes[0] != "/run/sysarmor" {
		t.Fatalf("sensor intent = %+v", got)
	}
	if got.ScopeType != "container" || got.ScopeSelector != "container-a" || !got.ObserveOnly {
		t.Fatalf("sensor scope = %+v", got)
	}
}
