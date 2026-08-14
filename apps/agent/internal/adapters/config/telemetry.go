package config

import (
	"fmt"
	"strings"
	"time"

	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

type EffectiveTelemetry struct {
	MaxBatchItems int
	MaxBatchBytes int
	FlushInterval time.Duration
}

func DefaultTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second}
}

func ResolveTelemetry(baseline TelemetryConfig, policy *policymodel.TelemetryPolicy) (EffectiveTelemetry, error) {
	effective := EffectiveTelemetry{MaxBatchItems: baseline.MaxBatchItems, MaxBatchBytes: baseline.MaxBatchBytes, FlushInterval: baseline.FlushInterval}
	if policy != nil {
		if policy.MaxBatchItems > 0 {
			effective.MaxBatchItems = policy.MaxBatchItems
		}
		if policy.MaxBatchBytes > 0 {
			effective.MaxBatchBytes = policy.MaxBatchBytes
		}
		if strings.TrimSpace(policy.FlushInterval) != "" {
			interval, err := time.ParseDuration(policy.FlushInterval)
			if err != nil {
				return EffectiveTelemetry{}, fmt.Errorf("telemetry.flush_interval: %w", err)
			}
			effective.FlushInterval = interval
		}
	}
	return effective, validateEffectiveTelemetry(effective)
}

func validateEffectiveTelemetry(value EffectiveTelemetry) error {
	if value.MaxBatchItems < 1 || value.MaxBatchItems > 4096 {
		return fmt.Errorf("telemetry.max_batch_items must be between 1 and 4096")
	}
	if value.MaxBatchBytes < 64<<10 || value.MaxBatchBytes > 16<<20 {
		return fmt.Errorf("telemetry.max_batch_bytes must be between 64KiB and 16MiB")
	}
	if value.FlushInterval < 100*time.Millisecond || value.FlushInterval > time.Minute {
		return fmt.Errorf("telemetry.flush_interval must be between 100ms and 1m")
	}
	return nil
}
