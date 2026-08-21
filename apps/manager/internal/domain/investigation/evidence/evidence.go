package evidence

import (
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/graph"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

func FromEvents(events []domaintelemetry.Event, signals []domaintelemetry.Signal) domaintelemetry.EvidenceSubgraph {
	return graph.FromEvents(events).ConnectingEvidence(signals)
}
