package daemon

import (
	"fmt"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type EndpointRuntime struct {
	runner     *AgentRuntime
	normalizer *eventadapter.EventNormalizer
}

func NewEndpointRuntime(runner *AgentRuntime, normalizer *eventadapter.EventNormalizer) *EndpointRuntime {
	return &EndpointRuntime{runner: runner, normalizer: normalizer}
}

func (r *EndpointRuntime) ProcessEvent(ev contract.EventEnvelope) (*dataplanev1.DataBatch, error) {
	if r == nil || r.runner == nil || r.normalizer == nil {
		return nil, fmt.Errorf("endpoint runtime is not initialized")
	}
	if ev.SensorEvent == nil {
		return nil, fmt.Errorf("sensor event is nil")
	}
	if ev.SensorEvent.RawRef == "" {
		ev.SensorEvent.RawRef = ev.RawRef
	}
	domainEvent := r.normalizer.NormalizeDomain(ev.SensorEvent)
	domainEvent.Labels = mergeLabels(domainEvent.Labels, r.runner.policyLabels())
	canonical := contractmapper.CanonicalEvent(domainEvent)
	signals := r.runner.currentDetection().Process(domainEvent)
	return r.runner.dataBatchForEvent(canonical, signals), nil
}

func (r *EndpointRuntime) ProcessSignals(signals []*signalv1.Signal) (*dataplanev1.DataBatch, error) {
	if r == nil || r.runner == nil {
		return nil, fmt.Errorf("endpoint runtime is not initialized")
	}
	return r.runner.dataBatchForSignals(signals), nil
}
