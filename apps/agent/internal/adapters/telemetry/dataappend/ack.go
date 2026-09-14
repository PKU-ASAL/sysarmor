package dataappend

import dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"

func AckCommitted(ack *dataplanev1.DataAck) bool {
	if ack == nil {
		return false
	}
	switch ack.GetStatus() {
	case dataplanev1.DataAck_STATUS_ACCEPTED, dataplanev1.DataAck_STATUS_DUPLICATE:
		return true
	case dataplanev1.DataAck_STATUS_UNSPECIFIED:
		return ack.GetAccepted()
	default:
		return false
	}
}

func AckRetryable(ack *dataplanev1.DataAck) bool {
	if ack == nil {
		return true
	}
	return ack.GetRetryable() || ack.GetStatus() == dataplanev1.DataAck_STATUS_RETRYABLE
}

func AckTerminalRejected(ack *dataplanev1.DataAck) bool {
	if ack == nil {
		return false
	}
	return ack.GetStatus() == dataplanev1.DataAck_STATUS_REJECTED && !ack.GetRetryable()
}
