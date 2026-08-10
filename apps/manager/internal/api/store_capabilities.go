package managerapi

import (
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type ManagerStore interface {
	identityStore
	policyControlStore
	telemetryStore
	operationalStore
}

type identityStore interface {
	AddAgent(store.AgentIdentity)
	CloseAgentSession(string, string, time.Time) store.AgentSession
	RecordDataBatchAppend(store.AgentIdentity, string, string, time.Time) store.AgentSession
	RecordAgentSessionSeen(string, string, time.Time) store.AgentSession
	RecordControlSessionOpen(string, string, string, time.Time) store.AgentSession
}

type policyControlStore interface {
	EffectivePolicyWithError(string, string, string, string) (policymodel.Policy, bool, error)
	EnsureDefaultPolicy(string)
	EnsureDefaultPolicyWithError(string) error
	ListAssignmentsWithError(string, string) ([]policymodel.Assignment, error)
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
	Info() store.Info
}

var _ ManagerStore = (*store.Store)(nil)
