package contracts

import (
	"reflect"
	"testing"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestSignalMapsDomainDetectionResult(t *testing.T) {
	value := detection.Signal{
		ID: "signal-a", Name: "rule-a", RuleID: "rule-a", RuleVersion: 7, RuleSetRef: "ruleset:a",
		Where: detection.SignalWhereEndpoint, BaseRisk: 80, Severity: "critical", Confidence: 91,
		Mode: "observe", LocalRarity: 0.5, GlobalRarity: 0.25, LineageID: "lineage-a",
		Entities:  []detection.Entity{{Kind: "process", Key: "process-a", Role: "subject"}},
		EventRefs: []string{"event-a"}, SignalRefs: []string{"signal-parent"}, Terminal: true, CrossLineage: true,
		ResponseIntent: &detection.ResponseIntent{Action: "collect_evidence", Confidence: 91, Reason: "test"},
		Evidence:       &detection.Evidence{ID: "evidence-a", EventRefs: []string{"event-a"}, RawRefs: []string{"raw-a"}, Summary: "summary"},
		ContextRefs:    []detection.ContentRef{{Ref: "ctx:a", Version: "v1", Digest: "sha256:a"}},
		IOCRefs:        []detection.ContentRef{{Ref: "ioc:a", Version: "v2", Digest: "sha256:b"}},
		Labels:         map[string]string{"env": "test"},
	}
	value.Evidence.Entities = append([]detection.Entity(nil), value.Entities...)

	wire := Signal(value)

	if wire.GetId() != value.ID || wire.GetWhere() != signalv1.SignalWhere_SIGNAL_WHERE_ENDPOINT || wire.GetRuleVersion() != 7 {
		t.Fatalf("signal = %+v", wire)
	}
	if !reflect.DeepEqual(wire.GetEventRefs(), value.EventRefs) || wire.GetEntities()[0].GetKey() != "process-a" {
		t.Fatalf("signal relations = %+v", wire)
	}
	if wire.GetEvidence().GetRawRefs()[0] != "raw-a" || wire.GetResponseIntent().GetRecommendedAction() != "collect_evidence" {
		t.Fatalf("signal evidence/intent = %+v", wire)
	}
	if wire.GetContextRefs()[0].GetDigest() != "sha256:a" || wire.GetIocRefs()[0].GetVersion() != "v2" || wire.GetLabels()["env"] != "test" {
		t.Fatalf("signal provenance = %+v", wire)
	}
}

func TestSignalClonesMutableDomainCollections(t *testing.T) {
	value := detection.Signal{EventRefs: []string{"event-a"}, Labels: map[string]string{"env": "test"}}
	wire := Signal(value)
	value.EventRefs[0] = "changed"
	value.Labels["env"] = "changed"
	if wire.GetEventRefs()[0] != "event-a" || wire.GetLabels()["env"] != "test" {
		t.Fatalf("wire signal aliases domain input: %+v", wire)
	}
}
