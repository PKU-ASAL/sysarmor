package ports

import (
	"context"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

type ControlFrame struct {
	TenantID, AgentID, SessionID, RequestID, Type string
	Sequence                                      uint64
	Payload                                       any
}

type ControlResult struct{ Frames []ControlFrame }
type ControlHandler interface {
	Handle(context.Context, ControlFrame) (ControlResult, error)
}

type ControlStateWriter interface {
	RecordHealth(context.Context, domainidentity.Health) error
	RecordCapability(context.Context, domaingateway.Capability) error
	AckResponse(context.Context, domaingateway.Ack) error
	AckCommand(context.Context, domaingateway.Ack) error
	CompleteEvidence(context.Context, domaingateway.EvidenceResult) error
}
