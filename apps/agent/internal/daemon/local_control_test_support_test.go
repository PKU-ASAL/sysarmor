package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
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

func newTestTelemetry(t testing.TB, runner *AgentRuntime) (*telemetry.Bus, *telemetry.Batcher, *telemetry.Sender) {
	t.Helper()
	installTestDetection(t, runner)
	bus := telemetry.NewBus(1024)
	batcher := telemetry.NewBatcher(runner.newDataBatch, 10, time.Hour, 16)
	sender := &telemetry.Sender{Appender: noopUploader{}, Batcher: batcher}
	return bus, batcher, sender
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
