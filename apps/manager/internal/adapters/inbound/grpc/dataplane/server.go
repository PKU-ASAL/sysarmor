package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	grpcauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/auth"
	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	dataplanecontract "github.com/sysarmor/sysarmor-next-project/packages/contracts/dataplane"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	"google.golang.org/grpc/codes"
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
	if !grpcauth.TokenAuthorized(ctx, server.token) {
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
	peer, ok := grpcauth.PeerIdentity(ctx)
	if !ok {
		return nil
	}
	tenantID := header.GetTenantId()
	if tenantID == "" {
		tenantID = "default"
	}
	if peer.TenantID != tenantID || peer.AgentID != header.GetAgentId() {
		return fmt.Errorf("mTLS identity mismatch")
	}
	if server.certificates == nil {
		return fmt.Errorf("certificate authorizer is required")
	}
	return server.certificates.Authorize(ctx, tenantID, peer.AgentID, peer.Serial)
}
func mapBatch(batch *dataplanev1.DataBatch) (ports.BatchEnvelope, error) {
	if batch == nil || batch.GetHeader() == nil {
		return ports.BatchEnvelope{}, fmt.Errorf("batch header identity is required")
	}
	if err := dataplanecontract.ValidateCandidateReferences(batch); err != nil {
		return ports.BatchEnvelope{}, err
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
	if strings.TrimSpace(header.GetEnrollmentEpoch()) == "" {
		return ports.BatchEnvelope{}, fmt.Errorf("batch enrollment_epoch is required")
	}
	return ports.BatchEnvelope{EnrollmentEpoch: header.GetEnrollmentEpoch(), TenantID: header.GetTenantId(), AgentID: header.GetAgentId(), HostID: header.GetHostId(), BatchID: header.GetBatchId(), Transport: "grpc_stream", Topic: "sysarmor.data.telemetry.endpoint.batch.ingress.v1", Key: header.GetTenantId() + ":" + key, Payload: raw}, nil
}
func acceptedAck(batch *dataplanev1.DataBatch, value dataplanev1.DataAck_Status, message string) *dataplanev1.DataAck {
	return &dataplanev1.DataAck{BatchId: batch.GetHeader().GetBatchId(), Accepted: true, Status: value, Message: message, ReasonCode: message, CommittedCursor: batch.GetHeader().GetBatchId(), ServerTime: time.Now().UTC().Format(time.RFC3339Nano), ContractVersion: "dataplane.v1"}
}
func rejectedAck(batch *dataplanev1.DataBatch, err error) *dataplanev1.DataAck {
	reason := "invalid_data_batch"
	var violation *dataplanecontract.ReferenceViolation
	if errors.As(err, &violation) {
		reason = string(violation.Code)
	}
	return &dataplanev1.DataAck{BatchId: batchID(batch), Status: dataplanev1.DataAck_STATUS_REJECTED, Message: err.Error(), ReasonCode: reason, ContractVersion: "dataplane.v1"}
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
