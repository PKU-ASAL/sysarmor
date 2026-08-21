package provenance

import (
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/investigation/entity"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
)

type ProvenanceEdge struct {
	ID         string
	From       string
	To         string
	Operation  string
	EventRefs  []string
	Incomplete bool
}

func FromEvent(event domaintelemetry.Event) (ProvenanceEdge, bool) {
	if event.SubjectProcess == nil || strings.TrimSpace(event.SubjectProcess.StableID) == "" {
		return ProvenanceEdge{}, false
	}
	subject := entityID("process", event.SubjectProcess.StableID)
	behavior := strings.ToLower(strings.TrimSpace(event.Behavior))
	var edge ProvenanceEdge
	switch behavior {
	case "process.exec", "process.fork", "process.clone":
		edge = processEdge(event, subject, strings.TrimPrefix(behavior, "process."))
	case "file.open", "file.read":
		edge = objectEdge(event, entityID("file", filePath(event)), subject, strings.TrimPrefix(behavior, "file."))
	case "file.write", "file.create", "file.chmod", "file.rename":
		edge = objectEdge(event, subject, entityID("file", filePath(event)), strings.TrimPrefix(behavior, "file."))
	case "network.connect", "network.send":
		edge = objectEdge(event, subject, entityID("socket", socketAddress(event)), strings.TrimPrefix(behavior, "network."))
	case "network.receive":
		edge = objectEdge(event, entityID("socket", socketAddress(event)), subject, "receive")
	default:
		return ProvenanceEdge{}, false
	}
	if edge.From == "" || edge.To == "" || edge.From == edge.To {
		return ProvenanceEdge{}, false
	}
	edge.ID = edge.Operation + ":" + edge.From + "->" + edge.To
	if event.ID != "" {
		edge.EventRefs = []string{event.ID}
	}
	return edge, true
}

func processEdge(event domaintelemetry.Event, subject, operation string) ProvenanceEdge {
	if event.ParentStableID != "" {
		return ProvenanceEdge{From: entityID("process", event.ParentStableID), To: subject, Operation: operation}
	}
	if event.IdentityStatus == "unavailable" {
		return ProvenanceEdge{From: "gap:parent:" + event.ID, To: subject, Operation: operation, Incomplete: true}
	}
	return ProvenanceEdge{}
}

func objectEdge(_ domaintelemetry.Event, from, to, operation string) ProvenanceEdge {
	return ProvenanceEdge{From: from, To: to, Operation: operation}
}

func entityID(kind, key string) string {
	if strings.TrimSpace(key) == "" {
		return ""
	}
	return entity.Normalize(domaintelemetry.Entity{Kind: kind, Key: key}).Key
}

func filePath(event domaintelemetry.Event) string {
	if event.Object == nil {
		return ""
	}
	return event.Object.FilePath
}

func socketAddress(event domaintelemetry.Event) string {
	if event.Object == nil {
		return ""
	}
	return event.Object.SocketAddress
}
