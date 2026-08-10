package gateway

type Ack struct{ TenantID, AgentID, ID, Status, Message, Error string }
type EvidenceResult struct {
	TenantID, AgentID, RequestID string
	OK                           bool
	Error                        string
	Evidence                     []byte
}
type Capability struct{ TenantID, AgentID, HostID, Version string }
