package telemetry

import (
	"sync"
	"sync/atomic"
)

type CandidateLifecycleSnapshot struct {
	Created, Spooled, GatewayAccepted, GatewayDuplicateAck uint64
	ContractRejected, GatewayRejected                      uint64
	DeliveryAttempted, GatewayRetryable, DeliveryErrors    uint64
	LastDeliveryError                                      string
}

type CandidateLifecycle struct {
	created, spooled, gatewayAccepted, gatewayDuplicateAck atomic.Uint64
	contractRejected, gatewayRejected                      atomic.Uint64
	deliveryAttempted, gatewayRetryable, deliveryErrors    atomic.Uint64
	errorMu                                                sync.RWMutex
	lastDeliveryError                                      string
}

func (lifecycle *CandidateLifecycle) RecordCreated(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.created.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordSpooled(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.spooled.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordGatewayAccepted(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.gatewayAccepted.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordGatewayDuplicateAck(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.gatewayDuplicateAck.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordContractRejected(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.contractRejected.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordGatewayRejected(count uint64) {
	if lifecycle == nil {
		return
	}
	lifecycle.gatewayRejected.Add(count)
}

func (lifecycle *CandidateLifecycle) RecordDeliveryAttempted(count uint64) {
	if lifecycle != nil {
		lifecycle.deliveryAttempted.Add(count)
	}
}

func (lifecycle *CandidateLifecycle) RecordGatewayRetryable(count uint64) {
	if lifecycle != nil {
		lifecycle.gatewayRetryable.Add(count)
	}
}

func (lifecycle *CandidateLifecycle) RecordDeliveryError(count uint64, message string) {
	if lifecycle == nil {
		return
	}
	lifecycle.deliveryErrors.Add(count)
	lifecycle.errorMu.Lock()
	lifecycle.lastDeliveryError = message
	lifecycle.errorMu.Unlock()
}

func (lifecycle *CandidateLifecycle) Snapshot() CandidateLifecycleSnapshot {
	if lifecycle == nil {
		return CandidateLifecycleSnapshot{}
	}
	lifecycle.errorMu.RLock()
	lastError := lifecycle.lastDeliveryError
	lifecycle.errorMu.RUnlock()
	return CandidateLifecycleSnapshot{
		Created: lifecycle.created.Load(), Spooled: lifecycle.spooled.Load(),
		GatewayAccepted: lifecycle.gatewayAccepted.Load(), GatewayDuplicateAck: lifecycle.gatewayDuplicateAck.Load(),
		ContractRejected:  lifecycle.contractRejected.Load(),
		GatewayRejected:   lifecycle.gatewayRejected.Load(),
		DeliveryAttempted: lifecycle.deliveryAttempted.Load(), GatewayRetryable: lifecycle.gatewayRetryable.Load(),
		DeliveryErrors: lifecycle.deliveryErrors.Load(), LastDeliveryError: lastError,
	}
}
