package gateway

import "sync/atomic"

type BatchMetricsSnapshot struct {
	BatchesReceived      uint64 `json:"batches_received"`
	BatchesPublished     uint64 `json:"batches_published"`
	BatchesPublishFailed uint64 `json:"batches_publish_failed"`
}

type BatchMetrics struct {
	received, published, publishFailed atomic.Uint64
}

func (metrics *BatchMetrics) Snapshot() BatchMetricsSnapshot {
	if metrics == nil {
		return BatchMetricsSnapshot{}
	}
	return BatchMetricsSnapshot{
		BatchesReceived:      metrics.received.Load(),
		BatchesPublished:     metrics.published.Load(),
		BatchesPublishFailed: metrics.publishFailed.Load(),
	}
}
