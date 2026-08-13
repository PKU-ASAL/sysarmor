package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

type localBatchSender struct{}

type localStoreBatchSender struct {
	store    *localstore.Store
	onCommit func(*dataplanev1.DataBatch)
}

var newLocalBatchSender = func() dataappend.BatchSender {
	return localBatchSender{}
}

func (localBatchSender) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	if batch == nil {
		return &dataplanev1.DataAck{Accepted: true, Status: dataplanev1.DataAck_STATUS_ACCEPTED}, nil
	}
	return &dataplanev1.DataAck{
		Accepted:        true,
		Status:          dataplanev1.DataAck_STATUS_ACCEPTED,
		BatchId:         batch.GetHeader().GetBatchId(),
		CommittedCursor: batch.GetHeader().GetBatchId(),
	}, nil
}

func (s *localStoreBatchSender) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	if batch == nil {
		return nil, fmt.Errorf("data batch is required")
	}
	if _, err := s.store.AppendBatch(context.Background(), batch); err != nil {
		return nil, err
	}
	if err := s.store.AppendSignals(context.Background(), batch.GetSignals()); err != nil {
		return nil, err
	}
	if _, err := s.store.EnforceCapacity(context.Background()); err != nil {
		return nil, fmt.Errorf("enforce local storage capacity: %w", err)
	}
	if s.onCommit != nil {
		s.onCommit(batch)
	}
	return &dataplanev1.DataAck{Accepted: true, Status: dataplanev1.DataAck_STATUS_ACCEPTED, BatchId: batch.GetHeader().GetBatchId(), CommittedCursor: batch.GetHeader().GetBatchId()}, nil
}

func (r *AgentRuntime) runtimeLabels(scopeType, scopeSelector, sensorRuntime string) map[string]string {
	labels := cloneStringMap(r.Config.Agent.Labels)
	if sensorRuntime != "" {
		labels["sensor_runtime"] = sensorRuntime
	}
	if scopeType != "" {
		labels["scope_type"] = scopeType
	}
	if scopeSelector != "" {
		labels["scope_selector"] = scopeSelector
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func (r *AgentRuntime) policyLabels() map[string]string {
	policy := r.activePolicy()
	labels := map[string]string{}
	if policy.PolicyID != "" {
		labels["policy_id"] = policy.PolicyID
	}
	if policy.Version > 0 {
		labels["policy_version"] = fmt.Sprintf("%d", policy.Version)
	}
	if policy.Mode != "" {
		labels["policy_mode"] = policy.Mode
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func cloneStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func mergeLabels(base, extra map[string]string) map[string]string {
	out := cloneStringMap(base)
	for key, value := range extra {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *AgentRuntime) dataBatchForEvent(event *eventv1.CanonicalEvent, signals []*signalv1.Signal) *dataplanev1.DataBatch {
	now := time.Now().UTC()
	batch := r.newDataBatch(now)
	if event != nil {
		batch.Events = append(batch.Events, &dataplanev1.EventFrame{
			Sequence:   event.GetSeq(),
			ObservedAt: now.Format(time.RFC3339Nano),
			Event:      event,
		})
	}
	for _, sig := range signals {
		sequence := r.nextSignalSequence()
		setEndpointSignalID(sig, sequence)
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{
			Sequence:   sequence,
			ObservedAt: now.Format(time.RFC3339Nano),
			Signal:     sig,
		})
	}
	return batch
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

func (r *AgentRuntime) dataBatchForSignals(signals []*signalv1.Signal) *dataplanev1.DataBatch {
	now := time.Now().UTC()
	batch := r.newDataBatch(now)
	policyLabels := r.policyLabels()
	for _, sig := range signals {
		if sig != nil {
			sig.Labels = mergeLabels(sig.GetLabels(), policyLabels)
		}
		batch.Signals = append(batch.Signals, &dataplanev1.SignalFrame{
			Sequence:   r.nextSignalSequence(),
			ObservedAt: now.Format(time.RFC3339Nano),
			Signal:     sig,
		})
	}
	return batch
}

func (r *AgentRuntime) newDataBatch(now time.Time) *dataplanev1.DataBatch {
	identity := r.currentIdentity()
	policy := r.activePolicy()
	labels := cloneStringMap(r.Config.Agent.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range r.policyLabels() {
		labels[key] = value
	}
	if len(labels) == 0 {
		labels = nil
	}
	return &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{
			TenantId:          identity.TenantID,
			AgentId:           identity.AgentID,
			HostId:            identity.HostID,
			PolicyId:          policy.PolicyID,
			PolicyVersion:     policy.Version,
			PolicyMode:        policy.Mode,
			CreatedAtUnixNano: now.UnixNano(),
			Labels:            labels,
		},
	}
}

func (r *AgentRuntime) nextSignalSequence() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signalSeq++
	return r.signalSeq
}
