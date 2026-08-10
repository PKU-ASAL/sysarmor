package control

import (
	"errors"
	"fmt"
	"io"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type Server struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	dispatcher *gatewayapp.Dispatcher
}

func NewServer(dispatcher *gatewayapp.Dispatcher) *Server { return &Server{dispatcher: dispatcher} }
func (server *Server) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		mapped, err := mapIncoming(frame)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		result, err := server.dispatcher.Dispatch(stream.Context(), mapped)
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		for _, reply := range result.Frames {
			if err := stream.Send(mapReply(frame, reply)); err != nil {
				return err
			}
		}
	}
}
func mapIncoming(frame *controlplanev1.ControlFrame) (ports.ControlFrame, error) {
	if frame == nil || frame.GetContext() == nil {
		return ports.ControlFrame{}, fmt.Errorf("control frame context is required")
	}
	ctx := frame.GetContext()
	tenantID := ctx.GetTenantId()
	if tenantID == "" {
		tenantID = "default"
	}
	result := ports.ControlFrame{TenantID: tenantID, AgentID: ctx.GetAgentId(), SessionID: tenantID + "/" + ctx.GetAgentId(), RequestID: frame.GetRequestId(), Type: frame.GetType(), Sequence: frame.GetSequence()}
	var err error
	result.Payload, err = mapPayload(frame, tenantID, ctx.GetAgentId())
	return result, err
}
func mapPayload(frame *controlplanev1.ControlFrame, tenantID, agentID string) (any, error) {
	switch frame.GetType() {
	case "health_report":
		raw, err := protojson.Marshal(frame.GetHealth())
		if err != nil {
			return nil, err
		}
		id, err := tenant.NewID(tenantID)
		if err != nil {
			return nil, err
		}
		health := frame.GetHealth()
		return domainidentity.Health{TenantID: id, AgentID: domainidentity.AgentID(agentID), HostID: health.GetHostId(), Status: health.GetStatus(), Scope: domainidentity.Scope{Type: health.GetScope().GetType(), Selector: health.GetScope().GetSelector()}, Document: raw}, nil
	case "capability_report":
		value := frame.GetCapability()
		return domaingateway.Capability{TenantID: tenantID, AgentID: agentID, HostID: value.GetHostId(), Version: value.GetSensor().GetVersion()}, nil
	case "response_ack":
		value := frame.GetResponseAck()
		statusValue := "failed"
		if value.GetAccepted() {
			statusValue = "completed"
		}
		return domaingateway.Ack{TenantID: tenantID, AgentID: agentID, ID: value.GetResponseId(), Status: statusValue, Message: value.GetMessage()}, nil
	case "ack":
		value := frame.GetAck()
		return domaingateway.Ack{TenantID: tenantID, AgentID: agentID, ID: value.GetRequestId(), Status: value.GetStatus(), Message: value.GetMessage()}, nil
	case "evidence_pullback_result":
		value := frame.GetEvidenceResult()
		return domaingateway.EvidenceResult{TenantID: tenantID, AgentID: agentID, RequestID: value.GetRequestId(), OK: value.GetOk(), Error: value.GetMessage(), Evidence: append([]byte(nil), value.GetEvidenceJson()...)}, nil
	default:
		return nil, nil
	}
}
func mapReply(request *controlplanev1.ControlFrame, reply ports.ControlFrame) *controlplanev1.ControlFrame {
	ack, _ := reply.Payload.(domaingateway.Ack)
	return &controlplanev1.ControlFrame{Type: reply.Type, RequestId: request.GetRequestId(), Context: request.GetContext(), ContractVersion: 1, Ack: &controlplanev1.ControlAck{RequestId: request.GetRequestId(), TenantId: request.GetContext().GetTenantId(), AgentId: request.GetContext().GetAgentId(), Status: ack.Status, Message: ack.Message}}
}
