package kafka

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanecontract "github.com/sysarmor/sysarmor-next-project/packages/contracts/dataplane"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/contracts/schema"
	"google.golang.org/protobuf/encoding/protojson"
)

type BatchDecoder struct{ now func() time.Time }

func NewBatchDecoder() *BatchDecoder { return &BatchDecoder{now: time.Now} }

func (decoder *BatchDecoder) Decode(message ports.RawMessage) (ports.DataBatch, error) {
	wire := &dataplanev1.DataBatch{}
	if err := protojson.Unmarshal(message.Value, wire); err != nil {
		return ports.DataBatch{}, contractmapper.PermanentMessage(message, "invalid_data_batch", err)
	}
	if _, err := schema.ValidateDataPlane(wire.GetSchemaVersion()); err != nil {
		return ports.DataBatch{}, contractmapper.PermanentMessage(message, "unsupported_schema_version", err)
	}
	if !validBatchIdentity(wire) {
		return ports.DataBatch{}, contractmapper.PermanentMessage(message, "invalid_data_batch", errors.New("batch identity is required"))
	}
	if err := dataplanecontract.ValidateCandidateReferences(wire); err != nil {
		failureClass := "invalid_data_batch"
		var violation *dataplanecontract.ReferenceViolation
		if errors.As(err, &violation) {
			failureClass = string(violation.Code)
		}
		rejection := ports.CandidateRejection{
			TenantID: wire.GetHeader().GetTenantId(), AgentID: wire.GetHeader().GetAgentId(), BatchID: wire.GetHeader().GetBatchId(),
			FailureClass: failureClass, Signals: candidateRejections(wire),
		}
		return ports.DataBatch{}, contractmapper.PermanentCandidateMessage(message, failureClass, err, rejection)
	}
	stabilizeBatchTime(wire, decoder.currentTime())
	batch, err := mapDataBatch(message, wire)
	if err != nil {
		return ports.DataBatch{}, contractmapper.PermanentMessage(message, "invalid_data_batch", err)
	}
	return batch, nil
}

func candidateRejections(batch *dataplanev1.DataBatch) []ports.RejectedSignal {
	values := dataplanecontract.ModelCandidateRejections(batch)
	result := make([]ports.RejectedSignal, 0, len(values))
	for _, value := range values {
		result = append(result, ports.RejectedSignal{SignalID: value.SignalID, EventSequence: value.EventSequence})
	}
	return result
}

func mapDataBatch(source ports.RawMessage, wire *dataplanev1.DataBatch) (ports.DataBatch, error) {
	header := wire.GetHeader()
	tenantID, err := tenant.NewID(header.GetTenantId())
	if err != nil {
		return ports.DataBatch{}, err
	}
	result := ports.DataBatch{
		Source: source, TenantID: tenantID, AgentID: identity.AgentID(header.GetAgentId()), ID: header.GetBatchId(),
		CreatedAt: time.Unix(0, header.GetCreatedAtUnixNano()).UTC(),
	}
	if result.Events, err = mapEvents(wire, tenantID); err != nil {
		return ports.DataBatch{}, err
	}
	if result.Signals, err = mapSignals(wire); err != nil {
		return ports.DataBatch{}, err
	}
	return result, nil
}

func mapEvents(batch *dataplanev1.DataBatch, tenantID tenant.ID) ([]ports.ObservedEvent, error) {
	result := make([]ports.ObservedEvent, 0, len(batch.GetEvents()))
	for index, frame := range batch.GetEvents() {
		wire := frame.GetEvent()
		if wire == nil {
			continue
		}
		if wire.GetTenantId() != "" && wire.GetTenantId() != tenantID.String() {
			return nil, fmt.Errorf("event %d tenant_id does not match batch identity", index)
		}
		wire.TenantId = tenantID.String()
		event, err := contractmapper.EventToDomain(wire)
		if err != nil {
			return nil, fmt.Errorf("map event %d: %w", index, err)
		}
		policy, err := detectionPolicyRef(event.Labels)
		if err != nil {
			return nil, fmt.Errorf("map event %d: %w", index, err)
		}
		result = append(result, ports.ObservedEvent{Event: event, ObservedAt: frameTime(frame.GetObservedAt(), batchTime(batch)), Policy: policy})
	}
	return result, nil
}

func mapSignals(batch *dataplanev1.DataBatch) ([]ports.ObservedSignal, error) {
	result := make([]ports.ObservedSignal, 0, len(batch.GetSignals()))
	for index, frame := range batch.GetSignals() {
		if frame.GetSignal() == nil {
			continue
		}
		signal, err := contractmapper.SignalToDomain(frame.GetSignal())
		if err != nil {
			return nil, fmt.Errorf("map signal %d: %w", index, err)
		}
		policy, err := detectionPolicyRef(signal.Labels)
		if err != nil {
			return nil, fmt.Errorf("map signal %d: %w", index, err)
		}
		result = append(result, ports.ObservedSignal{Signal: signal, ObservedAt: frameTime(frame.GetObservedAt(), batchTime(batch)), Policy: policy})
	}
	return result, nil
}

func detectionPolicyRef(labels map[string]string) (ports.DetectionPolicyRef, error) {
	policyID := strings.TrimSpace(labels["policy_id"])
	versionText := strings.TrimSpace(labels["policy_version"])
	if policyID == "" && versionText == "" {
		return ports.DetectionPolicyRef{}, fmt.Errorf("policy_id and policy_version are required")
	}
	if policyID == "" || versionText == "" {
		return ports.DetectionPolicyRef{}, fmt.Errorf("policy_id and policy_version must be provided together")
	}
	version, err := strconv.ParseUint(versionText, 10, 64)
	if err != nil || version == 0 {
		return ports.DetectionPolicyRef{}, fmt.Errorf("invalid policy_version %q", versionText)
	}
	return ports.DetectionPolicyRef{ID: domainpolicy.ID(policyID), Version: domainpolicy.Version(version)}, nil
}

func validBatchIdentity(batch *dataplanev1.DataBatch) bool {
	header := batch.GetHeader()
	return header != nil && header.GetBatchId() != "" && header.GetTenantId() != "" && header.GetAgentId() != ""
}

func (decoder *BatchDecoder) currentTime() time.Time {
	if decoder != nil && decoder.now != nil {
		return decoder.now().UTC()
	}
	return time.Now().UTC()
}

func stabilizeBatchTime(batch *dataplanev1.DataBatch, fallback time.Time) {
	latest := batch.GetHeader().GetCreatedAtUnixNano()
	for _, frame := range batch.GetEvents() {
		if eventTime := int64(frame.GetEvent().GetOccurredAtNs()); eventTime > latest {
			latest = eventTime
		}
		latest = latestObserved(latest, frame.GetObservedAt())
	}
	for _, frame := range batch.GetSignals() {
		latest = latestObserved(latest, frame.GetObservedAt())
	}
	if latest <= 0 {
		latest = fallback.UnixNano()
	}
	batch.Header.CreatedAtUnixNano = latest
}

func latestObserved(latest int64, raw string) int64 {
	if observed, err := time.Parse(time.RFC3339Nano, raw); err == nil && observed.UnixNano() > latest {
		return observed.UnixNano()
	}
	return latest
}

func batchTime(batch *dataplanev1.DataBatch) time.Time {
	return time.Unix(0, batch.GetHeader().GetCreatedAtUnixNano()).UTC()
}

func frameTime(raw string, fallback time.Time) time.Time {
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC()
	}
	return fallback.UTC()
}
