package telemetry

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
	"google.golang.org/protobuf/proto"
)

type BatchBuilder struct {
	context ports.TelemetryContextProvider

	mu        sync.Mutex
	signalSeq uint64
}

func NewBatchBuilder(context ports.TelemetryContextProvider, initialSignalSequence uint64) *BatchBuilder {
	return &BatchBuilder{context: context, signalSeq: initialSignalSequence}
}

func (builder *BatchBuilder) NewBatch(now time.Time) *dataplanev1.DataBatch {
	return newBatch(now, builder.telemetryContext())
}

func newBatch(now time.Time, context ports.TelemetryContext) *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{Header: &dataplanev1.BatchHeader{
		TenantId: context.TenantID, AgentId: context.AgentID, HostId: context.HostID,
		PolicyId: context.PolicyID, PolicyVersion: context.PolicyVersion, PolicyMode: context.PolicyMode,
		CreatedAtUnixNano: now.UnixNano(), Labels: contextLabels(context),
	}}
}

func (builder *BatchBuilder) ForEvent(now time.Time, event *eventv1.CanonicalEvent, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	batch := builder.NewBatch(now)
	if event != nil {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{
			Sequence: event.GetSeq(), ObservedAt: now.Format(time.RFC3339Nano), Event: event,
		})
	}
	for _, signal := range signals {
		sequence := builder.nextSignalSequence()
		cloned := cloneSignal(signal)
		setEndpointSignalID(cloned, sequence)
		batch.Signals = append(batch.Signals, signalFrame(now, sequence, cloned))
	}
	return batch
}

func (builder *BatchBuilder) ForSignals(now time.Time, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	context := builder.telemetryContext()
	batch := newBatch(now, context)
	labels := policyLabels(context)
	for _, signal := range signals {
		sequence := builder.nextSignalSequence()
		cloned := cloneSignal(signal)
		if cloned != nil {
			cloned.Labels = mergeLabels(cloned.GetLabels(), labels)
		}
		batch.Signals = append(batch.Signals, signalFrame(now, sequence, cloned))
	}
	return batch
}

func (builder *BatchBuilder) telemetryContext() ports.TelemetryContext {
	if builder == nil || builder.context == nil {
		return ports.TelemetryContext{}
	}
	return builder.context.TelemetryContext()
}

func (builder *BatchBuilder) nextSignalSequence() uint64 {
	builder.mu.Lock()
	defer builder.mu.Unlock()
	builder.signalSeq++
	return builder.signalSeq
}

func signalFrame(now time.Time, sequence uint64, signal *signalv1.Signal) *dataplanev1.SignalFrame {
	return &dataplanev1.SignalFrame{Sequence: sequence, ObservedAt: now.Format(time.RFC3339Nano), Signal: signal}
}

func cloneSignal(signal *signalv1.Signal) *signalv1.Signal {
	if signal == nil {
		return nil
	}
	return proto.Clone(signal).(*signalv1.Signal)
}

func setEndpointSignalID(signal *signalv1.Signal, sequence uint64) {
	if signal == nil {
		return
	}
	signal.Id = fmt.Sprintf("sig-%020d", sequence)
	if signal.Evidence != nil {
		signal.Evidence.Id = "evb-" + signal.Id
	}
}

func contextLabels(context ports.TelemetryContext) map[string]string {
	return mergeLabels(context.Labels, policyLabels(context))
}

func policyLabels(context ports.TelemetryContext) map[string]string {
	labels := map[string]string{}
	if context.PolicyID != "" {
		labels["policy_id"] = context.PolicyID
	}
	if context.PolicyVersion > 0 {
		labels["policy_version"] = fmt.Sprintf("%d", context.PolicyVersion)
	}
	if context.PolicyMode != "" {
		labels["policy_mode"] = context.PolicyMode
	}
	return labels
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for key, value := range base {
		if key = strings.TrimSpace(key); key != "" {
			out[key] = value
		}
	}
	for key, value := range extra {
		if key = strings.TrimSpace(key); key != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
