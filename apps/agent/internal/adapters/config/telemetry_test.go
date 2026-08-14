package config

import (
	"testing"
	"time"

	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
)

func TestResolveTelemetryUsesConfigBaselineAndPartialPolicy(t *testing.T) {
	baseline := TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second}
	effective, err := ResolveTelemetry(baseline, &policymodel.TelemetryPolicy{MaxBatchItems: 512})
	if err != nil {
		t.Fatal(err)
	}
	if effective.MaxBatchItems != 512 || effective.MaxBatchBytes != 256<<10 || effective.FlushInterval != time.Second {
		t.Fatalf("effective=%+v", effective)
	}
}

func TestResolveTelemetryRejectsOutOfBoundsPolicy(t *testing.T) {
	baseline := TelemetryConfig{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: time.Second}
	for name, policy := range map[string]policymodel.TelemetryPolicy{
		"items":    {MaxBatchItems: 4097},
		"bytes":    {MaxBatchBytes: 16<<20 + 1},
		"interval": {FlushInterval: "50ms"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolveTelemetry(baseline, &policy); err == nil {
				t.Fatal("invalid telemetry policy accepted")
			}
		})
	}
}
