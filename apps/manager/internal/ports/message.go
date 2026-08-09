package ports

import "context"

type ControlFrame struct {
	TenantID, AgentID, SessionID, RequestID, Type string
	Sequence                                      uint64
	Payload                                       any
}

type ControlResult struct{ Frames []ControlFrame }
type ControlHandler interface {
	Handle(context.Context, ControlFrame) (ControlResult, error)
}
