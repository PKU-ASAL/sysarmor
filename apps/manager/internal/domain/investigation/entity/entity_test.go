package entity

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestUniqueNormalizesAndDeduplicatesEntities(t *testing.T) {
	result := Unique([]domaintelemetry.Entity{
		{Kind: " Process ", Key: "pid-1", Role: " Subject "},
		{Kind: "process", Key: "process:pid-1", Role: "subject"},
		{Kind: "file", Key: "/tmp/payload", Role: "object"},
		{},
	})
	if len(result) != 2 || result[0].Key != "process:pid-1" || result[1].Key != "file:/tmp/payload" {
		t.Fatalf("entities = %+v", result)
	}
}
