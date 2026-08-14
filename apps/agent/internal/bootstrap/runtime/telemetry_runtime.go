package runtime

import (
	"context"
	"fmt"
	"strings"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry/dataappend"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
)

func (r *telemetryRuntime) newBatchBuilder() *telemetryadapter.BatchBuilder {
	return telemetryadapter.NewBatchBuilder(r, r.initialSignalSequence)
}

type localBatchSender struct{}

type localStoreBatchSender struct {
	store    *sqlite.Store
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

func (r *telemetryRuntime) runtimeLabels(scopeType, scopeSelector, sensorRuntime string) map[string]string {
	labels := cloneStringMap(r.config.Agent.Labels)
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

func (r *policyRuntime) policyLabels() map[string]string {
	context := r.telemetry.TelemetryContext()
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
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func (r *telemetryRuntime) TelemetryContext() ports.TelemetryContext {
	identity := r.management.currentIdentity()
	policy := r.policy.activePolicy()
	return ports.TelemetryContext{
		TenantID: identity.TenantID, AgentID: identity.AgentID, HostID: identity.HostID,
		PolicyID: policy.PolicyID, PolicyVersion: policy.Version, PolicyMode: policy.Mode,
		Labels: cloneStringMap(r.config.Agent.Labels),
	}
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
