package runtime

import (
	"fmt"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/contracts"
	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	applicationpipeline "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/pipeline"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type EndpointRuntime struct {
	runner     *Runtime
	normalizer *eventadapter.EventNormalizer
	pipeline   *applicationpipeline.Service
	batches    *telemetryadapter.BatchBuilder
}

func NewEndpointRuntime(runner *Runtime, normalizer *eventadapter.EventNormalizer, batches *telemetryadapter.BatchBuilder) *EndpointRuntime {
	return &EndpointRuntime{runner: runner, normalizer: normalizer, pipeline: applicationpipeline.New(&runtimeDetector{runner: runner}), batches: batches}
}

func (r *EndpointRuntime) ProcessEvent(ev contract.EventEnvelope) (*dataplanev1.DataBatch, error) {
	if r == nil || r.runner == nil || r.normalizer == nil || r.batches == nil {
		return nil, fmt.Errorf("endpoint runtime is not initialized")
	}
	if ev.SensorEvent == nil {
		return nil, fmt.Errorf("sensor event is nil")
	}
	if ev.SensorEvent.RawRef == "" {
		ev.SensorEvent.RawRef = ev.RawRef
	}
	domainEvent := r.normalizer.NormalizeDomain(ev.SensorEvent)
	result, err := r.pipeline.Process(domainEvent, r.runner.policyLabels())
	if err != nil {
		return nil, err
	}
	canonical := contractmapper.CanonicalEvent(result.Event)
	signals := make([]*signalv1.Signal, 0, len(result.Signals))
	for _, signal := range result.Signals {
		signals = append(signals, contractmapper.Signal(*signal))
	}
	return r.batches.ForEvent(time.Now().UTC(), canonical, signals), nil
}

func (r *EndpointRuntime) ProcessSignals(signals []*signalv1.Signal) (*dataplanev1.DataBatch, error) {
	if r == nil || r.runner == nil || r.batches == nil {
		return nil, fmt.Errorf("endpoint runtime is not initialized")
	}
	return r.batches.ForSignals(time.Now().UTC(), signals), nil
}
