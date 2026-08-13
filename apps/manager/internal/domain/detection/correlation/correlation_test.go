package correlation

import (
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestBuildFiltersRulesAndKeepsCommonLabels(t *testing.T) {
	events := []domaintelemetry.Event{{Labels: map[string]string{"tenant": "a", "scenario": "one"}}}
	signals := []domaintelemetry.Signal{
		{Name: "allowed", Labels: map[string]string{"tenant": "a", "scenario": "one"}},
		{Name: "blocked", Labels: map[string]string{"tenant": "a", "scenario": "two"}},
	}
	view := Build(events, signals, &detection.Policy{EndpointRules: []string{"allowed"}})
	if !view.Has("allowed") || view.Has("blocked") || view.Labels["tenant"] != "a" {
		t.Fatalf("view = %+v", view)
	}
	if _, ok := view.Labels["scenario"]; ok {
		t.Fatalf("non-common scenario retained: %+v", view.Labels)
	}
}

func TestCollectEntitiesReturnsNormalizedUniqueValues(t *testing.T) {
	view := Build(nil, []domaintelemetry.Signal{{Name: "exec", Entities: []domaintelemetry.Entity{
		{Kind: "process", Key: "p1", Role: "subject"}, {Kind: "process", Key: "process:p1", Role: "subject"},
	}}}, nil)
	entities := view.CollectEntities("exec")
	if len(entities) != 1 || entities[0].Key != "process:p1" {
		t.Fatalf("entities = %+v", entities)
	}
}
