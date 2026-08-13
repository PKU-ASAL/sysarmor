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
