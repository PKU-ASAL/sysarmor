package identity

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestDigestSignalsIgnoresAmbiguousEntityOrder(t *testing.T) {
	first := domaintelemetry.Entity{Kind: "a", Key: "b\x00c", Role: "d"}
	second := domaintelemetry.Entity{Kind: "a\x00b", Key: "c", Role: "d"}
	left := DigestSignals([]domaintelemetry.Signal{{Entities: []domaintelemetry.Entity{first, second}}}, nil)
	right := DigestSignals([]domaintelemetry.Signal{{Entities: []domaintelemetry.Entity{second, first}}}, nil)
	if left != right {
		t.Fatalf("digests differ: %q != %q", left, right)
	}
}

func TestDigestSignalsIncludesStageAndDetectorKind(t *testing.T) {
	base := domaintelemetry.Signal{Name: "exec", Stage: domaintelemetry.SignalStageCandidate, DetectorKind: domaintelemetry.DetectorKindRule}
	conclusion := base
	conclusion.Stage = domaintelemetry.SignalStageConclusion
	model := base
	model.DetectorKind = domaintelemetry.DetectorKindModel

	baseline := DigestSignals([]domaintelemetry.Signal{base}, nil)
	if baseline == DigestSignals([]domaintelemetry.Signal{conclusion}, nil) {
		t.Fatal("stage must affect signal digest")
	}
	if baseline == DigestSignals([]domaintelemetry.Signal{model}, nil) {
		t.Fatal("detector kind must affect signal digest")
	}
}
