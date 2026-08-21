package telemetry

import "sync/atomic"

type CandidateLifecycleSnapshot struct {
	Created, Spooled, GatewayAccepted, GatewayDuplicateAck uint64
	ContractRejected, GatewayRejected                      uint64
}

type CandidateLifecycle struct {
	created, spooled, gatewayAccepted, gatewayDuplicateAck atomic.Uint64
	contractRejected, gatewayRejected                      atomic.Uint64
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

func (lifecycle *CandidateLifecycle) Snapshot() CandidateLifecycleSnapshot {
	if lifecycle == nil {
		return CandidateLifecycleSnapshot{}
	}
	return CandidateLifecycleSnapshot{
		Created: lifecycle.created.Load(), Spooled: lifecycle.spooled.Load(),
		GatewayAccepted: lifecycle.gatewayAccepted.Load(), GatewayDuplicateAck: lifecycle.gatewayDuplicateAck.Load(),
		ContractRejected: lifecycle.contractRejected.Load(),
		GatewayRejected:  lifecycle.gatewayRejected.Load(),
	}
}
