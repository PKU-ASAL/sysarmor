package gateway

import "sync"

type BatchMetricsSnapshot struct {
	BatchesReceived      uint64 `json:"batches_received"`
	BatchesPublished     uint64 `json:"batches_published"`
	BatchesPublishFailed uint64 `json:"batches_publish_failed"`
}

type BatchMetrics struct {
	mu                                 sync.RWMutex
	received, published, publishFailed uint64
}

func (metrics *BatchMetrics) Snapshot() BatchMetricsSnapshot {
	if metrics == nil {
		return BatchMetricsSnapshot{}
	}
	metrics.mu.RLock()
	defer metrics.mu.RUnlock()
	return BatchMetricsSnapshot{
		BatchesReceived:      metrics.received,
		BatchesPublished:     metrics.published,
		BatchesPublishFailed: metrics.publishFailed,
	}
}

func (metrics *BatchMetrics) recordReceived() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.received++
}

func (metrics *BatchMetrics) recordPublished() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.published++
}

func (metrics *BatchMetrics) recordPublishFailed() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.publishFailed++
}
