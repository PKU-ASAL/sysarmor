package daemon

import (
	"context"
	"fmt"
	"time"

	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
)

func (r *AgentRuntime) shutdownAndReport(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, reporter healthReporter, startedAt time.Time, cancelDataPlane func(), stopRuntime func()) error {
	stopRuntime()
	grace := shutdownDrainTimeout(r.Config)
	shutdownStarted := time.Now()
	batcher.CloseAndFlush("shutdown")
	drained := waitForSenderDrained(sender, grace)
	timedOut := !drained
	cancelDataPlane()
	elapsed := time.Since(shutdownStarted)
	batcherStats := batcher.Stats()
	stats := sender.Stats()
	if r.Out != nil {
		fmt.Fprintf(r.Out, "agent shutdown telemetry: grace=%s elapsed=%s flushed_batches=%d queued_batches=%d sent_batches=%d sent_events=%d sent_signals=%d drained=%t timeout=%t last_batcher_error=%q last_sender_error=%q\n",
			grace, elapsed.Round(time.Millisecond), batcherStats.FlushedBatches, batcherStats.QueuedBatches, stats.SentBatches, stats.SentEvents, stats.SentSignals, drained, timedOut, batcherStats.LastError, stats.LastError)
	}
	finalHealth, healthErr := r.collectShutdownHealth(ctx, rt, bus, batcher, sender, startedAt)
	if healthErr == nil {
		if err := reporter.Report(context.Background(), finalHealth); err != nil && r.Out != nil {
			fmt.Fprintf(r.Out, "agent final health report error: %v\n", err)
		}
		if r.Out != nil {
			fmt.Fprintf(r.Out, "agent final health: sensor=%s running=%t policy_loaded=%t status=%s queued_batches=%d last_data_plane_error=%q\n",
				finalHealth.Sensor.Backend, finalHealth.Sensor.Running, finalHealth.Sensor.PolicyLoaded, finalHealth.Status, finalHealth.TelemetryBatcher.QueuedBatches, finalHealth.TelemetrySender.LastError)
		}
	}
	return nil
}

func (r *AgentRuntime) collectShutdownHealth(ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) (agenthealth.AgentHealth, error) {
	health, err := r.collectHealth(ctx, rt, bus, batcher, sender, startedAt)
	if err != nil {
		return agenthealth.AgentHealth{}, err
	}
	health.Sensor.Running = false
	if health.Status == "ok" {
		health.Status = "degraded"
	}
	health.ObservedAt = time.Now().UTC()
	return health, nil
}

func shutdownDrainTimeout(cfg config.Config) time.Duration {
	timeout := 5 * time.Second
	if cfg.Local.Export.RequestTimeout > 0 && cfg.Local.Export.RequestTimeout < timeout {
		timeout = cfg.Local.Export.RequestTimeout
	}
	return timeout
}

func waitForSenderDrained(sender *telemetryadapter.RuntimeSender, timeout time.Duration) bool {
	if sender == nil {
		return true
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if sender.Stats().Drained {
			return true
		}
		select {
		case <-deadline.C:
			return sender.Stats().Drained
		case <-ticker.C:
		}
	}
}
