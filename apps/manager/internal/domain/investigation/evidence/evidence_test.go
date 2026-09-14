package evidence

import (
	"testing"

	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func TestFromEventsMarksSignalSeedsWithoutEventNodesAsGaps(t *testing.T) {
	value := FromEvents(nil, []domaintelemetry.Signal{{Entities: []domaintelemetry.Entity{
		{Kind: "file", Key: "/dev/shm/x.sh", Role: "object"},
		{Kind: "file", Key: "file:/dev/shm/x.sh", Role: "object"},
		{Kind: "socket", Key: "10.66.0.99:443", Role: "object"},
	}}})
	if len(value.Nodes) != 2 || value.Nodes[0].ID != "gap:seed:file:/dev/shm/x.sh" || value.Nodes[0].Kind != "gap" || len(value.Edges) != 0 {
		t.Fatalf("evidence = %+v", value)
	}
}
