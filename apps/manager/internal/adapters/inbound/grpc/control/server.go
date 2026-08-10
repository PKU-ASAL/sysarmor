package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	grpcauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/grpc/auth"
	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
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
	dispatcher   *gatewayapp.Dispatcher
	certificates ports.AgentCertificateAuthorizer
	token        string
	connections  atomic.Uint64
	revocations  *gatewayapp.RevokeEnrollmentService
}

func NewServer(dispatcher *gatewayapp.Dispatcher, certificates ports.AgentCertificateAuthorizer, token string, revocations *gatewayapp.RevokeEnrollmentService) *Server {
	return &Server{dispatcher: dispatcher, certificates: certificates, token: token, revocations: revocations}
}

func (server *Server) RevokeEnrollment(ctx context.Context, request *controlplanev1.RevokeEnrollmentRequest) (*controlplanev1.RevokeEnrollmentResponse, error) {
	identity, ok := grpcauth.PeerIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "mTLS agent identity is required")
	}
	if server.revocations == nil {
		return nil, status.Error(codes.Internal, "revocation service is required")
	}
	result, err := server.revocations.Revoke(ctx, domaingateway.RevokeEnrollment{
		TenantID: request.GetTenantId(), AgentID: request.GetAgentId(), EnrollmentID: request.GetEnrollmentId(),
		CertificateSerial: request.GetCertificateSerial(), CompletionTokenHash: request.GetCompletionTokenHash(),
		PeerTenantID: identity.TenantID, PeerAgentID: identity.AgentID, PeerSerial: identity.Serial,
	})
	if err != nil {
		return nil, status.Error(failureCode(err), err.Error())
	}
	return &controlplanev1.RevokeEnrollmentResponse{Status: "revoked", RevokedAt: result.RevokedAt.UTC().Format(time.RFC3339Nano), ReceiptId: result.ReceiptID, CompletionRequired: result.CompletionRequired}, nil
}

func (server *Server) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	if !grpcauth.TokenAuthorized(stream.Context(), server.token) {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	connectionID := fmt.Sprintf("control-%d", server.connections.Add(1))
	var outgoing uint64
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		mapped, err := mapIncoming(frame, connectionID)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if err := server.authorizePeer(stream.Context(), mapped); err != nil {
			return err
		}
		result, err := server.dispatcher.Dispatch(stream.Context(), mapped)
		if err != nil {
			return dispatchError(err)
		}
		for _, reply := range result.Frames {
			mappedReply, err := mapReply(frame, reply)
			if err != nil {
				return status.Error(codes.Internal, err.Error())
			}
			outgoing++
			mappedReply.Sequence = outgoing
			if err := stream.Send(mappedReply); err != nil {
				return err
			}
		}
	}
}

func (server *Server) authorizePeer(ctx context.Context, frame ports.ControlFrame) error {
	identity, ok := grpcauth.PeerIdentity(ctx)
	if !ok {
		return nil
	}
	if identity.TenantID != frame.TenantID || identity.AgentID != frame.AgentID {
		return status.Error(codes.PermissionDenied, "mTLS identity mismatch")
	}
	if server.certificates == nil {
		return status.Error(codes.PermissionDenied, "certificate authorizer is required")
	}
	if err := server.certificates.Authorize(ctx, frame.TenantID, frame.AgentID, identity.Serial); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

func mapIncoming(frame *controlplanev1.ControlFrame, sessionID string) (ports.ControlFrame, error) {
	if frame == nil || frame.GetContext() == nil {
		return ports.ControlFrame{}, fmt.Errorf("control frame context is required")
	}
	if frame.GetContractVersion() != 1 {
		return ports.ControlFrame{}, fmt.Errorf("unsupported control contract_version %d", frame.GetContractVersion())
	}
	if frame.GetRequestId() == "" {
		return ports.ControlFrame{}, fmt.Errorf("control frame request_id is required")
	}
	ctx := frame.GetContext()
	tenantID := ctx.GetTenantId()
	if tenantID == "" {
		tenantID = "default"
	}
	result := ports.ControlFrame{TenantID: tenantID, AgentID: ctx.GetAgentId(), SessionID: sessionID, RequestID: frame.GetRequestId(), Type: frame.GetType(), Sequence: frame.GetSequence()}
	var err error
	result.Payload, err = mapPayload(frame, tenantID, ctx.GetAgentId())
	return result, err
}
func mapPayload(frame *controlplanev1.ControlFrame, tenantID, agentID string) (any, error) {
	switch frame.GetType() {
	case "hello":
		scope := frame.GetContext().GetScope()
		return domaingateway.Hello{ScopeType: scope.GetType(), ScopeSelector: scope.GetSelector()}, nil
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
		return domaingateway.Ack{TenantID: tenantID, AgentID: agentID, ID: value.GetResponseId(), Status: statusValue, Message: value.GetMessage(), Accepted: value.GetAccepted(), Unsupported: value.GetUnsupported(), ObserveOnly: value.GetObserveOnly(), Executed: value.GetExecuted(), ObservedAt: parseControlTime(value.GetObservedAt())}, nil
	case "ack":
		value := frame.GetAck()
		return domaingateway.Ack{TenantID: tenantID, AgentID: agentID, ID: value.GetRequestId(), Status: value.GetStatus(), Message: value.GetMessage(), PolicyID: value.GetPolicyId(), PolicyVersion: value.GetPolicyVersion(), ReportJSON: string(value.GetReportJson())}, nil
	case "evidence_pullback_result":
		value := frame.GetEvidenceResult()
		return domaingateway.EvidenceResult{TenantID: tenantID, AgentID: agentID, RequestID: value.GetRequestId(), OK: value.GetOk(), Error: value.GetMessage(), Evidence: append([]byte(nil), value.GetEvidenceJson()...), ObservedAt: parseControlTime(value.GetObservedAt())}, nil
	default:
		return nil, nil
	}
}
func mapReply(request *controlplanev1.ControlFrame, reply ports.ControlFrame) (*controlplanev1.ControlFrame, error) {
	frame := &controlplanev1.ControlFrame{Type: reply.Type, RequestId: reply.RequestID, Context: request.GetContext(), ContractVersion: 1}
	if frame.RequestId == "" {
		frame.RequestId = request.GetRequestId()
	}
	switch reply.Type {
	case "ack":
		ack, ok := reply.Payload.(domaingateway.Ack)
		if !ok {
			return nil, fmt.Errorf("control ack payload is invalid")
		}
		frame.Ack = &controlplanev1.ControlAck{RequestId: frame.RequestId, TenantId: request.GetContext().GetTenantId(), AgentId: request.GetContext().GetAgentId(), Status: ack.Status, Message: ack.Message}
	case "policy_update":
		raw, ok := reply.Payload.([]byte)
		if !ok {
			return nil, fmt.Errorf("policy update payload is invalid")
		}
		frame.PolicyUpdate = &controlplanev1.CurrentPolicyResponse{}
		if err := protojson.Unmarshal(raw, frame.PolicyUpdate); err != nil {
			return nil, fmt.Errorf("decode policy update: %w", err)
		}
		frame.PolicyUpdate.RawJson = string(raw)
	case "resume":
		state, ok := reply.Payload.(domaingateway.OpenSession)
		if !ok {
			return nil, fmt.Errorf("resume payload is invalid")
		}
		frame.Resume = &controlplanev1.ResumeCursor{TenantId: state.TenantID, AgentId: state.AgentID, SessionId: state.SessionID, ResumeCursor: state.ResumeCursor}
	case "response_command":
		message, ok := reply.Payload.(domaingateway.Message)
		if !ok {
			return nil, fmt.Errorf("response command payload is invalid")
		}
		frame.ResponseCommand = &controlplanev1.ResponseCommand{}
		if err := protojson.Unmarshal(message.Document, frame.ResponseCommand); err != nil {
			return nil, fmt.Errorf("decode response command: %w", err)
		}
		frame.ResponseCommand.RawJson = string(message.Document)
	case "evidence_pullback":
		message, ok := reply.Payload.(domaingateway.Message)
		if !ok {
			return nil, fmt.Errorf("evidence pullback payload is invalid")
		}
		frame.EvidencePullback = &controlplanev1.EvidencePullbackRequest{}
		if err := protojson.Unmarshal(message.Document, frame.EvidencePullback); err != nil {
			return nil, fmt.Errorf("decode evidence pullback: %w", err)
		}
		frame.EvidencePullback.RawJson = string(message.Document)
	case "control_command":
		if err := mapControlCommand(frame, reply.Payload); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported control reply type %q", reply.Type)
	}
	return frame, nil
}

func mapControlCommand(frame *controlplanev1.ControlFrame, payload any) error {
	message, ok := payload.(domaingateway.Message)
	if !ok {
		return fmt.Errorf("control command payload is invalid")
	}
	var command struct {
		Type        string          `json:"type"`
		PayloadJSON json.RawMessage `json:"payload_json"`
	}
	if err := json.Unmarshal(message.Document, &command); err != nil {
		return fmt.Errorf("decode control command: %w", err)
	}
	frame.Type = command.Type
	frame.PayloadJson = append([]byte(nil), command.PayloadJSON...)
	switch command.Type {
	case "policy_update":
		frame.PolicyUpdate = &controlplanev1.CurrentPolicyResponse{}
		if err := protojson.Unmarshal(command.PayloadJSON, frame.PolicyUpdate); err != nil {
			return fmt.Errorf("decode policy command: %w", err)
		}
		frame.PolicyUpdate.RawJson = string(command.PayloadJSON)
	case "content_update":
		frame.ContentUpdate = &controlplanev1.ApplyContentRequest{Context: frame.Context, ContentJson: string(command.PayloadJSON)}
	default:
		return fmt.Errorf("unsupported control command type %q", command.Type)
	}
	return nil
}

func dispatchError(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "unknown"), strings.Contains(message, "required"):
		return status.Error(codes.InvalidArgument, message)
	case strings.Contains(message, "replay"):
		return status.Error(codes.AlreadyExists, message)
	case strings.Contains(message, "gap"):
		return status.Error(codes.FailedPrecondition, message)
	default:
		return status.Error(codes.Internal, message)
	}
}

func failureCode(err error) codes.Code {
	switch failure.KindOf(err) {
	case failure.InvalidArgument:
		return codes.InvalidArgument
	case failure.Unauthenticated:
		return codes.Unauthenticated
	case failure.PermissionDenied, failure.Conflict:
		return codes.PermissionDenied
	case failure.NotFound:
		return codes.NotFound
	case failure.FailedPrecondition:
		return codes.FailedPrecondition
	case failure.ResourceExhausted:
		return codes.ResourceExhausted
	case failure.RetryableDependency:
		return codes.Unavailable
	default:
		return codes.Internal
	}
}

func parseControlTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
