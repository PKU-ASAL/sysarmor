package platforme2e

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/api"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/gateway"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestAgentGatewayManagerLocalDataPath(t *testing.T) {
	st := &store.Store{}
	runtime := gateway.NewRuntime(gateway.RuntimeOptions{
		Store:          st,
		LocalProcessor: ingestworker.NewProcessor(st, nil),
	})

	grpcServer := grpc.NewServer()
	gateway.RegisterAgentServices(grpcServer, runtime)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen gateway: %v", err)
	}
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.DialContext(context.Background(), lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	managerHandler := managerapi.NewServer(st).Handler()
	manager := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := managerauth.Principal{Subject: "platform-viewer", TenantID: "default", Roles: []string{"viewer"}}
		managerHandler.ServeHTTP(w, r.WithContext(managerauth.WithPrincipal(r.Context(), principal)))
	}))
	t.Cleanup(manager.Close)

	batch := &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{
			BatchId:  "platform-local-batch-1",
			AgentId:  "platform-local-agent",
			HostId:   "platform-local-host",
			TenantId: "default",
		},
		Events: []*dataplanev1.EventFrame{{
			Event: &eventv1.CanonicalEvent{
				Id:       "platform-local-event-1",
				AgentId:  "platform-local-agent",
				HostId:   "platform-local-host",
				TenantId: "default",
				Behavior: "process.exec",
				Labels: map[string]string{
					"scenario": "agent-gateway-manager-local",
				},
				OccurredAtNs: uint64(time.Now().UnixNano()),
			},
		}},
	}
	ack, err := appendStreamBatch(context.Background(), conn, batch)
	if err != nil {
		t.Fatalf("stream batch: %v", err)
	}
	if !ack.GetAccepted() || ack.GetAcceptedEvents() != 1 {
		t.Fatalf("ack = %+v, want one accepted event", ack)
	}
	if runtime.MetricsSnapshot().AcceptedEvents != 1 {
		t.Fatalf("gateway metrics = %+v, want accepted event", runtime.MetricsSnapshot())
	}

	body := get(t, manager.URL+"/api/v1/events?label=scenario=agent-gateway-manager-local")
	if !strings.Contains(body, "platform-local-event-1") {
		t.Fatalf("manager events missing uploaded event: %s", body)
	}
	if len(st.Agents) != 1 || st.Agents[0].AgentID != "platform-local-agent" {
		t.Fatalf("gateway-bound agents = %+v", st.Agents)
	}
}

func appendStreamBatch(ctx context.Context, conn *grpc.ClientConn, batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	stream, err := dataplanev1.NewAgentDataPlaneServiceClient(conn).StreamBatches(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.Send(batch); err != nil {
		_ = stream.CloseSend()
		return nil, err
	}
	ack, err := stream.Recv()
	if err != nil {
		_ = stream.CloseSend()
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	return ack, nil
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", url, resp.StatusCode, body)
	}
	return string(body)
}
