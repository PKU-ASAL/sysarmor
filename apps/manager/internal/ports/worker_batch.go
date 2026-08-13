package ports

import (
	"context"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type DetectionPolicyRef struct {
	ID      domainpolicy.ID
	Version domainpolicy.Version
}

type ObservedEvent struct {
	Event      domaintelemetry.Event
	ObservedAt time.Time
	Policy     DetectionPolicyRef
}

type ObservedSignal struct {
	Signal     domaintelemetry.Signal
	ObservedAt time.Time
	Policy     DetectionPolicyRef
}

type DataBatch struct {
	Source    RawMessage
	TenantID  tenant.ID
	AgentID   identity.AgentID
	ID        string
	CreatedAt time.Time
	Events    []ObservedEvent
	Signals   []ObservedSignal
}

type BatchProjection struct {
	Source       RawMessage
	TenantID     tenant.ID
	AgentID      identity.AgentID
	ObservedAt   time.Time
	Events       []ObservedEvent
	Signals      []ObservedSignal
	CloudSignals []ObservedSignal
	Incidents    []domaintelemetry.Incident
}

type BatchDecoder interface {
	Decode(RawMessage) (DataBatch, error)
}

type BatchProjector interface {
	Project(context.Context, BatchProjection) error
}
