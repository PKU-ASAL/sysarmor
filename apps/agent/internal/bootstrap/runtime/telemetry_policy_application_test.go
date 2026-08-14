package runtime

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
)

func TestTelemetryProductionPathAcceptsNestedDocumentAndReconfiguresBatcher(t *testing.T) {
	store := openEndpointPolicyStore(t)
	t.Cleanup(func() { _ = store.Close() })
	endpoint := parseEndpointPolicy(t, standaloneEndpointPolicyJSON)
	if err := agentpolicy.SaveEffectiveEndpointPolicy(t.Context(), store, endpoint); err != nil {
		t.Fatal(err)
	}
	runner := &Runtime{Config: config.Config{Telemetry: config.DefaultTelemetryConfig()}, localStore: store}
	runner.setEndpointPolicy(endpoint)
	batcher := telemetryadapter.NewBatcher(nil, 10, time.Hour, 2, 12345)
	result := newApplicationPolicyController(runner, nil, batcher).ApplyPolicy(t.Context(), agentcontrol.PolicyCommand{
		PolicyType: "telemetry", Source: agentcontrol.PolicySourceStandalone,
		Document: `{"telemetry":{"max_batch_items":32,"max_batch_bytes":65536,"flush_interval":"1s"}}`,
	})
	if result.Status != "applied" {
		t.Fatalf("result=%+v", result)
	}
	effective := runner.currentEffectiveTelemetry()
	if effective.MaxBatchItems != 32 || effective.MaxBatchBytes != 65536 || effective.FlushInterval != time.Second {
		t.Fatalf("effective=%+v", effective)
	}
	if stats := batcher.Stats(); stats.MaxBytes != 65536 {
		t.Fatalf("batcher stats=%+v", stats)
	}
}
