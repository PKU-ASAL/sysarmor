package managerapi

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
)

type ManagerStore interface {
	identityStore
	policyControlStore
	enrollmentStore
	artifactStore
	telemetryStore
	operationalStore
}

type identityStore interface {
	AddAgent(store.AgentIdentity)
	CloseAgentSession(string, string, time.Time) store.AgentSession
	RecordDataBatchAppend(store.AgentIdentity, string, string, time.Time) store.AgentSession
	RecordAgentSessionSeen(string, string, time.Time) store.AgentSession
	RecordControlSessionOpen(string, string, string, time.Time) store.AgentSession
	UpsertAgentHealth(agenthealth.AgentHealth)
}

type policyControlStore interface {
	AckControlCommand(controlmodel.ControlCommandAck) (controlmodel.ControlCommand, bool, error)
	AckResponse(responsemodel.Ack) (responsemodel.Command, bool, error)
	ApproveResponse(string, string, string, bool, string, string, string) (responsemodel.Command, bool)
	AssignPolicyWithAudit(policymodel.Assignment, policymodel.AuditRecord, *controlmodel.ControlCommand) (policymodel.Assignment, *controlmodel.ControlCommand, bool, error)
	CancelControlCommand(string, string, string, string, string) (controlmodel.ControlCommand, bool)
	CompleteEvidencePullback(controlmodel.EvidencePullbackResult) (controlmodel.EvidencePullbackRequest, bool)
	CreateControlCommand(controlmodel.ControlCommand) (controlmodel.ControlCommand, error)
	CreateEvidencePullback(controlmodel.EvidencePullbackRequest) controlmodel.EvidencePullbackRequest
	CreateResponse(responsemodel.Command) (responsemodel.Command, error)
	EffectivePolicyWithError(string, string, string, string) (policymodel.Policy, bool, error)
	EnsureDefaultPolicy(string)
	EnsureDefaultPolicyWithError(string) error
	GetEvidencePullbackWithError(string, string, string) (controlmodel.EvidencePullbackRequest, bool, error)
	GetPolicyWithError(string, string, uint64) (policymodel.Policy, bool, error)
	ListAssignmentsWithError(string, string) ([]policymodel.Assignment, error)
	ListControlCommandsWithError(string, string, string) ([]controlmodel.ControlCommand, error)
	ListEvidencePullbacksWithError(string, string) ([]controlmodel.EvidencePullbackRequest, error)
	ListPoliciesWithError(string) ([]policymodel.Policy, error)
	ListPolicyAuditsWithError(string, string) ([]policymodel.AuditRecord, error)
	ListResponsesWithError(string, string) ([]responsemodel.AuditRecord, error)
	ListRules(string) []policymodel.RuleContent
	PendingResponsesWithError(string, string) ([]responsemodel.Command, error)
	PublishPolicyWithAudit(string, string, uint64, bool, policymodel.AuditRecord) (policymodel.Policy, bool, error)
	RecordPolicyAudit(policymodel.AuditRecord) policymodel.AuditRecord
	RetryControlCommand(string, string, string, string, string) (controlmodel.ControlCommand, bool)
	ExpireControlCommand(string, string, string, string) (controlmodel.ControlCommand, bool)
	UpsertPolicyWithError(policymodel.Policy) (policymodel.Policy, error)
}

type enrollmentStore interface {
	CompleteAgentUnenrollment(string, string, string, string, string, string, time.Time) (store.UnenrollmentRecord, bool, error)
	ConsumeEnrollmentBootstrap(string, string, string, time.Time) (store.Enrollment, bool, error)
	CreateEnrollment(store.Enrollment) store.Enrollment
	CommitEnrollmentIssue(string, string, store.Enrollment, store.AgentCertificate) (store.Enrollment, store.EnrollmentIssueResult, error)
	GetEnrollmentByBootstrapTokenHashWithError(string) (store.Enrollment, bool, error)
	GetEnrollmentByTokenHashWithError(string) (store.Enrollment, bool, error)
	ListEnrollmentsWithError(string, string) ([]store.Enrollment, error)
	ListUnenrollmentsWithError(string) ([]store.UnenrollmentRecord, error)
	MarkEnrollmentUsed(string, time.Time) (store.Enrollment, bool)
	RecordAgentCertificate(store.AgentCertificate) store.AgentCertificate
}

type artifactStore interface {
	GetArtifactWithError(string, string) (store.Artifact, bool, error)
	GetChannelWithError(string, string) (store.ArtifactChannel, bool, error)
	ListArtifactsWithError(string, string, string) ([]store.Artifact, error)
	ListChannelsWithError(string) ([]store.ArtifactChannel, error)
	UpsertArtifact(store.Artifact) store.Artifact
	UpsertChannel(store.ArtifactChannel) store.ArtifactChannel
}

type telemetryStore interface {
	AddEvent(*eventv1.CanonicalEvent) bool
	AddSignal(*signalv1.Signal) bool
	AddSignalForTenant(string, *signalv1.Signal) bool
	GetSignalForTenant(string, string) (*signalv1.Signal, bool)
	ListEvents(store.LabelSelector, string) []*eventv1.CanonicalEvent
	ListEventsForTenant(string, store.LabelSelector, string) []*eventv1.CanonicalEvent
	ListIncidents(store.LabelSelector) []*incidentv1.Incident
	ListIncidentsForTenant(string, store.LabelSelector) []*incidentv1.Incident
	ListSignals(store.LabelSelector, string, bool) []*signalv1.Signal
	ListSignalsForTenant(string, store.LabelSelector, string, bool) []*signalv1.Signal
}

type operationalStore interface {
	DeleteByLabels(store.LabelSelector)
	Info() store.Info
	MetricsSnapshotForTenant(string) store.Metrics
	Save() error
}

var _ ManagerStore = (*store.Store)(nil)
