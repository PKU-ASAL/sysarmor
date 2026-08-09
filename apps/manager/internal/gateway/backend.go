package gateway

import (
	"errors"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

var ErrInvalidUpload = errors.New("invalid upload")

const (
	DataAckReasonAccepted             = "accepted"
	DataAckReasonDuplicate            = "duplicate"
	DataAckReasonInvalidUpload        = "invalid_data_batch"
	DataAckReasonRetryableServerError = "retryable_server_error"
	DataAckReasonServerError          = "server_error"
	DataAckReasonRetryable            = "retryable"
	DataAckReasonRejected             = "rejected"
	DataAckReasonUnspecified          = "unspecified"
)

type DataAppendResult struct {
	AcceptedEvents  int
	AcceptedSignals int
	CloudSignals    int
	Incidents       int
	Duplicate       bool
}

type Backend interface {
	AgentToken() string
	AppendDataBatchWithTransport(*dataplanev1.DataBatch, string) (DataAppendResult, error)
	BindAgentIdentity(store.AgentIdentity) error
	Store() ControlStore
	TouchHotSession(store.AgentSession)
}

type ControlStore interface {
	AckResponse(responsemodel.Ack) (responsemodel.Command, bool, error)
	AddAgent(store.AgentIdentity)
	AttachIncidentEvidence(string, store.LabelSelector, *incidentv1.EvidenceSubgraph) (*incidentv1.Incident, bool)
	CompleteEvidencePullback(controlmodel.EvidencePullbackResult) (controlmodel.EvidencePullbackRequest, bool)
	AckControlCommand(controlmodel.ControlCommandAck) (controlmodel.ControlCommand, bool, error)
	AuthorizeAgentUnenrollment(string, string, string, string, string, time.Time) (store.UnenrollmentRecord, bool, error)
	EffectivePolicyWithError(string, string, string, string) (policymodel.Policy, bool, error)
	GetEvidencePullbackWithError(string, string, string) (controlmodel.EvidencePullbackRequest, bool, error)
	GetAgentCertificateWithError(string, string) (store.AgentCertificate, bool, error)
	MarkControlCommandSent(string, string, string, time.Time) (controlmodel.ControlCommand, bool)
	PendingControlCommandsWithError(string, string) ([]controlmodel.ControlCommand, error)
	PendingEvidencePullbacksWithError(string, string) ([]controlmodel.EvidencePullbackRequest, error)
	PendingResponsesWithError(string, string) ([]responsemodel.Command, error)
	RecordControlSessionOpen(string, string, string, time.Time) store.AgentSession
	RevokeAgentCertificate(string, string, string, string, time.Time) (store.AgentCertificate, bool, error)
	Save() error
	UpsertAgentHealth(agenthealth.AgentHealth)
}
