package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type Server struct {
	dataplanev1.UnimplementedAgentDataPlaneServiceServer
	acceptor     *gatewayapp.BatchAcceptor
	certificates ports.AgentCertificateAuthorizer
	token        string
}

func NewServer(acceptor *gatewayapp.BatchAcceptor, certificates ports.AgentCertificateAuthorizer, token string) *Server {
	return &Server{acceptor: acceptor, certificates: certificates, token: token}
}
func (server *Server) StreamBatches(stream dataplanev1.AgentDataPlaneService_StreamBatchesServer) error {
	for {
		batch, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		ack, err := server.accept(stream.Context(), batch)
		if err != nil {
			return err
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
	}
}
func (server *Server) accept(ctx context.Context, batch *dataplanev1.DataBatch) (*dataplanev1.DataAck, error) {
	if !authorized(ctx, server.token) {
		return nil, status.Error(codes.Unauthenticated, "unauthorized")
	}
	if err := server.authorizePeer(ctx, batch.GetHeader()); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	envelope, err := mapBatch(batch)
	if err != nil {
		return rejectedAck(batch, err), nil
	}
	result, err := server.acceptor.Accept(ctx, envelope)
	if err != nil {
		return retryableAck(batch, err), nil
	}
	statusValue, message := dataplanev1.DataAck_STATUS_ACCEPTED, "accepted"
	if result.Duplicate {
		statusValue, message = dataplanev1.DataAck_STATUS_DUPLICATE, "duplicate"
	}
	return acceptedAck(batch, statusValue, message), nil
}
func (server *Server) authorizePeer(ctx context.Context, header *dataplanev1.BatchHeader) error {
	peer, ok := peerIdentity(ctx)
	if !ok {
		return nil
	}
	tenantID := header.GetTenantId()
	if tenantID == "" {
		tenantID = "default"
	}
	if peer.tenantID != tenantID || peer.agentID != header.GetAgentId() {
		return fmt.Errorf("mTLS identity mismatch")
	}
	if server.certificates == nil {
		return fmt.Errorf("certificate authorizer is required")
	}
	return server.certificates.Authorize(ctx, tenantID, peer.agentID, peer.serial)
}

type identity struct{ tenantID, agentID, serial string }

func peerIdentity(ctx context.Context) (identity, bool) {
	value, ok := peer.FromContext(ctx)
	if !ok {
		return identity{}, false
	}
	info, ok := value.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return identity{}, false
	}
	cert := info.State.PeerCertificates[0]
	for _, uri := range cert.URIs {
		if result, ok := identityURI(uri); ok {
			result.serial = cert.SerialNumber.String()
			return result, true
		}
	}
	parts := strings.SplitN(strings.TrimSpace(cert.Subject.CommonName), "/", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return identity{tenantID: parts[0], agentID: parts[1], serial: cert.SerialNumber.String()}, true
	}
	return identity{}, false
}

func identityURI(uri *url.URL) (identity, bool) {
	parts := strings.Split(strings.Trim(uri.Path, "/"), "/")
	for index := 0; index+3 < len(parts); index++ {
		if parts[index] == "tenant" && parts[index+2] == "agent" && parts[index+1] != "" && parts[index+3] != "" {
			return identity{tenantID: parts[index+1], agentID: parts[index+3]}, true
		}
	}
	return identity{}, false
}
func mapBatch(batch *dataplanev1.DataBatch) (ports.BatchEnvelope, error) {
	if batch == nil || batch.GetHeader() == nil {
		return ports.BatchEnvelope{}, fmt.Errorf("batch header identity is required")
	}
	header := batch.GetHeader()
	raw, err := protojson.Marshal(batch)
	if err != nil {
		return ports.BatchEnvelope{}, err
	}
	key := header.GetAgentId()
	for _, label := range []string{"case_type", "scenario", "workload"} {
		if value := strings.TrimSpace(header.GetLabels()[label]); value != "" {
			key = label + "=" + value
			break
		}
	}
	return ports.BatchEnvelope{TenantID: header.GetTenantId(), AgentID: header.GetAgentId(), HostID: header.GetHostId(), BatchID: header.GetBatchId(), Transport: "grpc_stream", Topic: "sysarmor.agent.databatch.raw", Key: header.GetTenantId() + ":" + key, Payload: raw}, nil
}
func authorized(ctx context.Context, token string) bool {
	if token == "" {
		return true
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, value := range append(md.Get("x-sysarmor-agent-token"), md.Get("authorization")...) {
		if value == token || value == "Bearer "+token {
			return true
		}
	}
	return false
}
func acceptedAck(batch *dataplanev1.DataBatch, value dataplanev1.DataAck_Status, message string) *dataplanev1.DataAck {
	return &dataplanev1.DataAck{BatchId: batch.GetHeader().GetBatchId(), Accepted: true, Status: value, Message: message, ReasonCode: message, CommittedCursor: batch.GetHeader().GetBatchId(), ServerTime: time.Now().UTC().Format(time.RFC3339Nano), ContractVersion: "dataplane.v1"}
}
func rejectedAck(batch *dataplanev1.DataBatch, err error) *dataplanev1.DataAck {
	return &dataplanev1.DataAck{BatchId: batchID(batch), Status: dataplanev1.DataAck_STATUS_REJECTED, Message: err.Error(), ReasonCode: "invalid_data_batch", ContractVersion: "dataplane.v1"}
}
func retryableAck(batch *dataplanev1.DataBatch, err error) *dataplanev1.DataAck {
	return &dataplanev1.DataAck{BatchId: batchID(batch), Status: dataplanev1.DataAck_STATUS_RETRYABLE, Message: err.Error(), ReasonCode: "retryable_server_error", Retryable: true, RetryAfterMs: 1000, ContractVersion: "dataplane.v1"}
}
func batchID(batch *dataplanev1.DataBatch) string {
	if batch == nil {
		return ""
	}
	return batch.GetHeader().GetBatchId()
}
