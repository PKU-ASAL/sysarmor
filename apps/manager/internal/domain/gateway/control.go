package gateway

import "time"

type Ack struct {
	TenantID, AgentID, ID, Status, Message, Error string
	PolicyID                                      string
	PolicyVersion                                 uint64
	ReportJSON                                    string
	Accepted, Unsupported, ObserveOnly, Executed  bool
	ObservedAt                                    time.Time
}
type EvidenceResult struct {
	TenantID, AgentID, RequestID string
	OK                           bool
	Error                        string
	Evidence                     []byte
	ObservedAt                   time.Time
}
type Capability struct{ TenantID, AgentID, HostID, Version string }

type OpenSession struct {
	TenantID, AgentID, SessionID, ResumeCursor string
	PolicyDocument                             []byte
	Messages                                   []Message
}

type Hello struct {
	ScopeType     string
	ScopeSelector string
}
type Message struct {
	Type, ID string
	Document []byte
}

type Certificate struct {
	TenantID, AgentID, EnrollmentID, Serial, Protocol string
}

type RevokeEnrollment struct {
	TenantID, AgentID, EnrollmentID, CertificateSerial, CompletionTokenHash string
	PeerTenantID, PeerAgentID, PeerSerial                                   string
}

type Revocation struct {
	ReceiptID          string
	RevokedAt          time.Time
	CompletionRequired bool
}
