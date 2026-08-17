package evidence

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestFromEventsBuildsDeduplicatedSeedNodes(t *testing.T) {
	value := FromEvents(nil, []domaintelemetry.Signal{{Entities: []domaintelemetry.Entity{
		{Kind: "file", Key: "/dev/shm/x.sh", Role: "object"},
		{Kind: "file", Key: "file:/dev/shm/x.sh", Role: "object"},
		{Kind: "socket", Key: "10.66.0.99:443", Role: "object"},
	}}})
	if len(value.Nodes) != 2 || value.Nodes[0].ID != "file:/dev/shm/x.sh" {
		t.Fatalf("evidence = %+v", value)
	}
}
