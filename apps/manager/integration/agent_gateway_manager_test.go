package platforme2e

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	datagrpc "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/dataplane"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/api"
	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	ingestworker "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ingest"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestAgentGatewayManagerLocalDataPath(t *testing.T) {
	st := &store.Store{}
	publisher := projectionPublisher{processor: ingestworker.NewProcessor(st, nil)}
	acceptor := gatewayapp.NewBatchAcceptor(publisher, &integrationSessions{}, nil)

	grpcServer := grpc.NewServer()
	dataplanev1.RegisterAgentDataPlaneServiceServer(grpcServer, datagrpc.NewServer(acceptor, nil, ""))
	lis := bufconn.Listen(1 << 20)
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = lis.Close()
	})

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	managerHandler := managerapi.NewServer(st).Handler()
	manager := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := managerauth.Principal{Subject: "platform-viewer", TenantID: "default", Roles: []string{"viewer"}}
		managerHandler.ServeHTTP(w, r.WithContext(managerauth.WithPrincipal(r.Context(), principal)))
	})

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
	if !ack.GetAccepted() {
		t.Fatalf("ack = %+v, want accepted", ack)
	}

	body := get(t, manager, "/api/v1/events?label=scenario=agent-gateway-manager-local")
	if !strings.Contains(body, "platform-local-event-1") {
		t.Fatalf("manager events missing uploaded event: %s", body)
	}
	if len(st.Agents) != 1 || st.Agents[0].AgentID != "platform-local-agent" {
		t.Fatalf("gateway-bound agents = %+v", st.Agents)
	}
}

type projectionPublisher struct {
	processor *ingestworker.Processor
}

func (publisher projectionPublisher) Publish(ctx context.Context, envelope ports.BatchEnvelope) error {
	batch := &dataplanev1.DataBatch{}
	if err := protojson.Unmarshal(envelope.Payload, batch); err != nil {
		return err
	}
	_, err := publisher.processor.Process(ctx, batch)
	return err
}

type integrationSessions struct {
	seen map[string]bool
}

func (sessions *integrationSessions) IsDuplicate(_ context.Context, tenantID, agentID, batchID string) (bool, error) {
	return sessions.seen[tenantID+"/"+agentID+"/"+batchID], nil
}

func (sessions *integrationSessions) RecordBatch(_ context.Context, batch ports.BatchEnvelope) (ports.GatewaySession, error) {
	if sessions.seen == nil {
		sessions.seen = map[string]bool{}
	}
	sessions.seen[batch.TenantID+"/"+batch.AgentID+"/"+batch.BatchID] = true
	return ports.GatewaySession{TenantID: batch.TenantID, AgentID: batch.AgentID, Cursor: batch.BatchID}, nil
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

func get(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}
