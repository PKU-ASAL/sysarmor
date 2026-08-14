package runtime

import (
	"context"
	"net"
	"testing"
	"time"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
	runner.policyController = newApplicationPolicyController
	ensureTestLocalStore(t, runner)
	installTestDetection(t, runner)
	bus := telemetryadapter.NewBus(1024)
	batcher := telemetryadapter.NewBatcher(runner.newTelemetryBatchBuilder().NewBatch, 10, time.Hour, 16)
	sender := telemetryadapter.NewRuntimeSender(batcher, noopUploader{}, 0, 0)
	return bus, batcher, sender
}

func ensureTestLocalStore(t testing.TB, runner *Coordinator) {
	t.Helper()
	if runner.localStore == nil {
		store, err := sqlite.Open(context.Background(), sqlite.Options{RootDir: t.TempDir()})
		if err != nil {
			t.Fatalf("open test local store: %v", err)
		}
		runner.localStore = store
		t.Cleanup(func() { _ = store.Close() })
	}
	stored, ok, err := agentpolicy.LoadEndpointPolicy(context.Background(), runner.localStore, sqlite.PolicySourceStandalone)
	if err != nil {
		t.Fatalf("load standalone endpoint policy: %v", err)
	}
	if ok {
		runner.setEndpointPolicy(stored)
		return
	}
	endpoint := runner.currentEndpointPolicy()
	if endpoint.PolicyID == "" {
		endpoint = runner.activePolicy().EndpointPolicy()
	}
	if err := agentpolicy.SaveEffectiveEndpointPolicy(context.Background(), runner.localStore, endpoint); err != nil {
		t.Fatalf("initialize standalone endpoint policy: %v", err)
	}
	runner.setEndpointPolicy(endpoint)
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
