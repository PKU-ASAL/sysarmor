package runtime

import (
	"context"
	"net"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func startTestLocalControlServer(runner *Coordinator, ctx context.Context, rt sensorruntime.Runtime, bus *telemetryadapter.Bus, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time) (func(), error) {
	runner.wireComponents()
	runner.policyState.controller = newTestPolicyController
	control := localControlRuntime{
		config: runner.Config, out: runner.Out, policy: &runner.policyState, management: &runner.managementState,
		sensor: &runner.sensorState,
	}
	return control.start(ctx, rt, bus, batcher, sender, startedAt)
}

func newTestTransportRuntime(runner *Coordinator, sensor sensorruntime.Runtime, batcher *telemetryadapter.Batcher, sender *telemetryadapter.RuntimeSender, startedAt time.Time, scopeType, scopeSelector string) *TransportRuntime {
	runner.wireComponents()
	runner.policyState.controller = newTestPolicyController
	bus := telemetryadapter.NewBus(runner.Config.Telemetry.MaxBatchItems * 16)
	return NewTransportRuntime(transportRuntimeDependencies{
		config: runner.Config, out: runner.Out, sensorPort: runner.Sensor, policy: &runner.policyState,
		management: &runner.managementState, sensorState: &runner.sensorState,
	}, sensor, bus, batcher, sender, startedAt, scopeType, scopeSelector)
}

type noopUploader struct{}

func (noopUploader) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	return &dataplanev1.DataAck{Accepted: true, BatchId: batch.GetHeader().GetBatchId()}, nil
}

type recordingUploader struct {
	ch chan *dataplanev1.DataBatch
}

func newRecordingUploader() *recordingUploader {
	return &recordingUploader{ch: make(chan *dataplanev1.DataBatch, 16)}
}

func (u *recordingUploader) SendBatch(batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	if u != nil && batch != nil {
		u.ch <- batch
	}
	return (&noopUploader{}).SendBatch(batch)
}

func newTestTelemetry(t testing.TB, runner *Coordinator) (*telemetryadapter.Bus, *telemetryadapter.Batcher, *telemetryadapter.RuntimeSender) {
	t.Helper()
	runner.wireComponents()
	runner.policyState.controller = newTestPolicyController
	ensureTestLocalStore(t, runner)
	installTestDetection(t, runner)
	bus := telemetryadapter.NewBus(1024)
	batcher := telemetryadapter.NewBatcher(runner.telemetryState.newBatchBuilder().NewBatch, 10, time.Hour, 16)
	sender := telemetryadapter.NewRuntimeSender(batcher, noopUploader{}, 0, 0)
	return bus, batcher, sender
}

func ensureTestLocalStore(t testing.TB, runner *Coordinator) {
	t.Helper()
	runner.wireComponents()
	if runner.managementState.localStore == nil {
		store, err := sqlite.Open(context.Background(), sqlite.Options{RootDir: t.TempDir()})
		if err != nil {
			t.Fatalf("open test local store: %v", err)
		}
		runner.managementState.localStore = store
		t.Cleanup(func() { _ = store.Close() })
	}
	stored, ok, err := agentpolicy.LoadEndpointPolicy(context.Background(), runner.managementState.localStore, sqlite.PolicySourceStandalone)
	if err != nil {
		t.Fatalf("load standalone endpoint policy: %v", err)
	}
	if ok {
		runner.policyState.setEndpointPolicy(stored)
		return
	}
	endpoint := runner.policyState.currentEndpointPolicy()
	if endpoint.PolicyID == "" {
		endpoint = runner.policyState.activePolicy().EndpointPolicy()
	}
	if err := agentpolicy.SaveEffectiveEndpointPolicy(context.Background(), runner.managementState.localStore, endpoint); err != nil {
		t.Fatalf("initialize standalone endpoint policy: %v", err)
	}
	runner.policyState.setEndpointPolicy(endpoint)
}

func newUnixControlClient(t *testing.T, socketPath string) controlplanev1.AgentControlPlaneServiceClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	conn, err := grpc.DialContext(ctx, "unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial unix control socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return controlplanev1.NewAgentControlPlaneServiceClient(conn)
}
