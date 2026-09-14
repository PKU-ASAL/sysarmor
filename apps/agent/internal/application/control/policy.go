package control

import "context"

type PolicySource string

const (
	PolicySourceStandalone PolicySource = "standalone"
	PolicySourceManaged    PolicySource = "managed"
)

type PolicyCommand struct {
	Context    RequestContext
	PolicyType string
	Document   string
	DryRun     bool
	Telemetry  *TelemetryPolicy
	Source     PolicySource
}

type TelemetryPolicy struct {
	MaxBatchItems uint32
	MaxBatchBytes uint32
	FlushInterval string
}

type PendingPolicy struct {
	PolicyID string
	Version  uint64
	Status   string
	Message  string
	Source   PolicySource
	Digest   string
}

type PolicySnapshot struct {
	PolicyID      string
	Version       uint64
	TenantID      string
	ScopeType     string
	ScopeSelector string
	Mode          string
	EndpointRules []string
	CloudRules    []string
	Published     bool
	RawJSON       string
	Pending       *PendingPolicy
}

type PolicyController interface {
	ApplyPolicy(context.Context, PolicyCommand) Result
	CurrentPolicy(context.Context) (PolicySnapshot, error)
}
