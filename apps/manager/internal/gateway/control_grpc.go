package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
	controlmodel "github.com/sysarmor/sysarmor-next-project/packages/contracts/controlmodel"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	incidentv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/incident/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	responsemodel "github.com/sysarmor/sysarmor-next-project/packages/response"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type ControlServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	backend Backend
}

const maxControlReplayCache = 1024

func NewControlServer(backend Backend) controlplanev1.AgentControlPlaneServiceServer {
	return &ControlServer{backend: backend}
}

func (s *ControlServer) RevokeEnrollment(ctx context.Context, req *controlplanev1.RevokeEnrollmentRequest) (*controlplanev1.RevokeEnrollmentResponse, error) {
	peerID, ok := tlsconfig.PeerAgentIdentity(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "mTLS agent identity is required")
	}
	if req.GetTenantId() != peerID.TenantID || req.GetAgentId() != peerID.AgentID {
		return nil, status.Error(codes.PermissionDenied, "certificate identity does not match revocation request")
	}
	registered, found, err := s.backend.Store().GetAgentCertificateWithError(peerID.TenantID, peerID.CertificateSerial)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read agent certificate: %v", err)
	}
	if !found || registered.AgentID != peerID.AgentID {
		return nil, status.Error(codes.PermissionDenied, "agent certificate is not registered")
	}
	protocol := strings.TrimSpace(registered.UnenrollmentProtocol)
	if protocol == "" {
		protocol = controlmodel.UnenrollmentProtocolLegacyMTLS
	}
	if strings.TrimSpace(req.GetCompletionTokenHash()) == "" {
		if protocol != controlmodel.UnenrollmentProtocolLegacyMTLS {
			return nil, status.Error(codes.PermissionDenied, "certificate does not allow legacy unenrollment")
		}
		return s.revokeLegacyEnrollment(peerID, registered, req)
	}
	if protocol != controlmodel.UnenrollmentProtocolCompletionV1 {
		return nil, status.Error(codes.PermissionDenied, "certificate requires legacy unenrollment")
	}
	if req.GetCertificateSerial() != peerID.CertificateSerial {
		return nil, status.Error(codes.PermissionDenied, "certificate identity does not match revocation request")
	}
	if !validCompletionTokenHash(req.GetCompletionTokenHash()) {
		return nil, status.Error(codes.InvalidArgument, "completion token hash is invalid")
	}
	record, found, err := s.backend.Store().AuthorizeAgentUnenrollment(req.GetTenantId(), req.GetAgentId(), req.GetEnrollmentId(),
		req.GetCertificateSerial(), req.GetCompletionTokenHash(), time.Now().UTC())
	if errors.Is(err, store.ErrConflict) {
		return nil, status.Error(codes.PermissionDenied, "certificate enrollment identity mismatch")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "authorize enrollment revocation: %v", err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "agent certificate not found")
	}
	return &controlplanev1.RevokeEnrollmentResponse{
		Status: "revoked", RevokedAt: record.RevokedAt.UTC().Format(time.RFC3339Nano), ReceiptId: record.RevocationReceipt, CompletionRequired: true,
	}, nil
}

func validCompletionTokenHash(value string) bool {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(raw) == sha256.Size
}

func (s *ControlServer) revokeLegacyEnrollment(peerID tlsconfig.PeerIdentity, registered store.AgentCertificate, req *controlplanev1.RevokeEnrollmentRequest) (*controlplanev1.RevokeEnrollmentResponse, error) {
	if serial := strings.TrimSpace(req.GetCertificateSerial()); serial != "" && serial != peerID.CertificateSerial {
		return nil, status.Error(codes.PermissionDenied, "certificate identity does not match revocation request")
	}
	if enrollmentID := strings.TrimSpace(req.GetEnrollmentId()); enrollmentID != "" && enrollmentID != registered.EnrollmentID {
		return nil, status.Error(codes.PermissionDenied, "certificate enrollment identity mismatch")
	}
	cert, found, err := s.backend.Store().RevokeAgentCertificate(
		registered.TenantID, registered.AgentID, registered.EnrollmentID, registered.SerialNumber, time.Now().UTC(),
	)
	if errors.Is(err, store.ErrConflict) {
		return nil, status.Error(codes.PermissionDenied, "certificate enrollment identity mismatch")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke enrollment certificate: %v", err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "agent certificate not found")
	}
	return &controlplanev1.RevokeEnrollmentResponse{
		Status: "revoked", RevokedAt: cert.RevokedAt.UTC().Format(time.RFC3339Nano), ReceiptId: cert.RevocationReceipt,
	}, nil
}

func (s *ControlServer) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	if !s.authorized(stream.Context()) {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	state := controlConnectionState{nextIncoming: 1, nextOutgoing: 1, repliesByRequestID: map[string][]*controlplanev1.ControlFrame{}}
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "recv control frame: %v", err)
		}
		if err := state.acceptIncoming(frame); err != nil {
			out := []*controlplanev1.ControlFrame{controlAckFrame(frame, "rejected", err.Error(), errorCode(err), errorRetryable(err))}
			state.assignOutgoing(out)
			for _, reply := range out {
				if err := stream.Send(reply); err != nil {
					return status.Errorf(codes.Internal, "send control frame: %v", err)
				}
			}
			continue
		}
		if out, ok := state.replay(frame.GetRequestId()); ok {
			state.assignOutgoing(out)
			for _, reply := range out {
				if err := stream.Send(reply); err != nil {
					return status.Errorf(codes.Internal, "send control frame: %v", err)
				}
			}
			continue
		}
		out, err := s.handleFrame(stream.Context(), frame)
		if err != nil {
			out = []*controlplanev1.ControlFrame{controlAckFrame(frame, "rejected", err.Error(), errorCode(err), errorRetryable(err))}
		}
		state.remember(frame.GetRequestId(), out)
		state.assignOutgoing(out)
		for _, reply := range out {
			if err := stream.Send(reply); err != nil {
				return status.Errorf(codes.Internal, "send control frame: %v", err)
			}
		}
	}
}

type controlConnectionState struct {
	nextIncoming       uint64
	nextOutgoing       uint64
	repliesByRequestID map[string][]*controlplanev1.ControlFrame
	replayOrder        []string
}

func (s *controlConnectionState) acceptIncoming(frame *controlplanev1.ControlFrame) error {
	if frame == nil {
		return status.Error(codes.InvalidArgument, "control frame is nil")
	}
	if frame.GetContractVersion() != 1 {
		return status.Errorf(codes.InvalidArgument, "unsupported control contract_version %d", frame.GetContractVersion())
	}
	if frame.GetRequestId() == "" {
		return status.Error(codes.InvalidArgument, "control frame request_id is required")
	}
	seq := frame.GetSequence()
	if seq == 0 {
		return status.Error(codes.InvalidArgument, "control frame sequence is required")
	}
	if seq < s.nextIncoming {
		return status.Errorf(codes.AlreadyExists, "control frame replay sequence %d; expected %d", seq, s.nextIncoming)
	}
	if seq > s.nextIncoming {
		return status.Errorf(codes.FailedPrecondition, "control frame sequence gap: got %d; expected %d", seq, s.nextIncoming)
	}
	s.nextIncoming++
	return nil
}

func (s *controlConnectionState) remember(requestID string, frames []*controlplanev1.ControlFrame) {
	if requestID == "" {
		return
	}
	if s.repliesByRequestID == nil {
		s.repliesByRequestID = map[string][]*controlplanev1.ControlFrame{}
	}
	if _, exists := s.repliesByRequestID[requestID]; !exists {
		s.replayOrder = append(s.replayOrder, requestID)
	}
	s.repliesByRequestID[requestID] = cloneControlFrames(frames)
	for len(s.replayOrder) > maxControlReplayCache {
		oldest := s.replayOrder[0]
		s.replayOrder = s.replayOrder[1:]
		delete(s.repliesByRequestID, oldest)
	}
}

func (s *controlConnectionState) replay(requestID string) ([]*controlplanev1.ControlFrame, bool) {
	if requestID == "" {
		return nil, false
	}
	frames, ok := s.repliesByRequestID[requestID]
	if !ok {
		return nil, false
	}
	return cloneControlFrames(frames), true
}

func cloneControlFrames(frames []*controlplanev1.ControlFrame) []*controlplanev1.ControlFrame {
	out := make([]*controlplanev1.ControlFrame, 0, len(frames))
	for _, frame := range frames {
		if frame == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, proto.Clone(frame).(*controlplanev1.ControlFrame))
	}
	return out
}

func (s *controlConnectionState) assignOutgoing(frames []*controlplanev1.ControlFrame) {
	for _, frame := range frames {
		if frame == nil {
			continue
		}
		frame.ContractVersion = 1
		frame.Sequence = s.nextOutgoing
		s.nextOutgoing++
	}
}

func (s *ControlServer) handleFrame(ctx context.Context, frame *controlplanev1.ControlFrame) ([]*controlplanev1.ControlFrame, error) {
	if frame == nil {
		return nil, status.Error(codes.InvalidArgument, "control frame is nil")
	}
	peerID, hasPeer, err := validatePeerControlIdentity(ctx, frame.GetContext())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if hasPeer {
		if err := validatePeerCertificate(s.backend.Store(), peerID); err != nil {
			return nil, err
		}
		reqCtx := frame.GetContext()
		version := ""
		hostID := ""
		switch frame.GetType() {
		case "health_report":
			hostID = frame.GetHealth().GetHostId()
			version = frame.GetHealth().GetCapability().GetVersion()
		case "capability_report":
			hostID = frame.GetCapability().GetHostId()
			version = frame.GetCapability().GetSensor().GetVersion()
		}
		if reqCtx.GetAgentId() != "" {
			agent := agentIdentityFromPeer(peerID, hostID, version)
			if err := s.backend.BindAgentIdentity(agent); err != nil {
				return nil, status.Error(codes.PermissionDenied, err.Error())
			}
		}
	}
	switch frame.GetType() {
	case "hello":
		ctx := frame.GetContext()
		if ctx.GetAgentId() == "" {
			return nil, status.Error(codes.InvalidArgument, "hello agent_id is required")
		}
		tenantID := ctx.GetTenantId()
		if tenantID == "" {
			tenantID = "default"
		}
		scope := ctx.GetScope()
		st := s.backend.Store()
		policy, _, err := st.EffectivePolicyWithError(tenantID, ctx.GetAgentId(), scope.GetType(), scope.GetSelector())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read effective policy: %v", err)
		}
		responses, err := st.PendingResponsesWithError(tenantID, ctx.GetAgentId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read pending responses: %v", err)
		}
		pullbacks, err := st.PendingEvidencePullbacksWithError(tenantID, ctx.GetAgentId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read pending evidence pullbacks: %v", err)
		}
		commands, err := st.PendingControlCommandsWithError(tenantID, ctx.GetAgentId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read pending control commands: %v", err)
		}
		sessionBackend, ok := s.backend.(interface{ SessionApplication() SessionApplication })
		if !ok || sessionBackend.SessionApplication() == nil {
			return nil, status.Error(codes.Internal, "session application is not configured")
		}
		resumeValue, err := sessionBackend.SessionApplication().Resume(context.Background(), tenantID, ctx.GetAgentId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read resume cursor: %v", err)
		}
		resume := ResumeCursor{TenantID: tenantID, AgentID: ctx.GetAgentId()}
		resume.SessionID, resume.ResumeCursor = resumeValue.SessionID, resumeValue.Cursor
		st.AddAgent(store.AgentIdentity{AgentID: ctx.GetAgentId(), TenantID: tenantID})
		session := st.RecordControlSessionOpen(tenantID, ctx.GetAgentId(), "control", time.Now().UTC())
		s.backend.TouchHotSession(session)
		replies := []*controlplanev1.ControlFrame{{
			Type:            "policy_update",
			RequestId:       "policy-" + frame.GetRequestId(),
			Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: ctx.GetAgentId(), RequestId: "policy-" + frame.GetRequestId(), Scope: ctx.GetScope()},
			ContractVersion: 1,
			PolicyUpdate:    currentPolicyFrame(policy),
		}, {
			Type:            "resume",
			RequestId:       frame.GetRequestId(),
			Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: ctx.GetAgentId(), Scope: ctx.GetScope()},
			ContractVersion: 1,
			Resume:          resumeCursorFrame(resume),
		}}
		for _, cmd := range responses {
			replies = append(replies, &controlplanev1.ControlFrame{
				Type:            "response_command",
				RequestId:       frame.GetRequestId(),
				Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: ctx.GetAgentId(), Scope: ctx.GetScope()},
				ContractVersion: 1,
				ResponseCommand: responseCommandControlFrame(cmd),
			})
		}
		for _, req := range pullbacks {
			replies = append(replies, &controlplanev1.ControlFrame{
				Type:             "evidence_pullback",
				RequestId:        frame.GetRequestId(),
				Context:          &controlplanev1.RequestContext{TenantId: tenantID, AgentId: ctx.GetAgentId(), Scope: ctx.GetScope()},
				ContractVersion:  1,
				EvidencePullback: evidencePullbackControlFrame(req),
			})
		}
		for _, cmd := range commands {
			cmdFrame, err := controlCommandFrame(cmd, ctx.GetScope())
			if err != nil {
				return nil, status.Errorf(codes.Internal, "build control command frame: %v", err)
			}
			if cmdFrame != nil {
				replies = append(replies, cmdFrame)
				st.MarkControlCommandSent(cmd.CommandID, tenantID, ctx.GetAgentId(), time.Now().UTC())
			}
		}
		if err := st.Save(); err != nil {
			return nil, status.Errorf(codes.Internal, "save control hello state: %v", err)
		}
		return replies, nil
	case "health_report":
		health := agentHealthFromControl(frame.GetHealth())
		if health.AgentID == "" {
			return nil, status.Error(codes.InvalidArgument, "health_report agent_id is required")
		}
		st := s.backend.Store()
		st.UpsertAgentHealth(health)
		st.AddAgent(store.AgentIdentity{AgentID: health.AgentID, HostID: health.HostID, TenantID: health.TenantID, Version: health.Capability.Version})
		if err := st.Save(); err != nil {
			return nil, status.Errorf(codes.Internal, "save health: %v", err)
		}
		return []*controlplanev1.ControlFrame{controlAckFrame(frame, "accepted", "health accepted", "", false)}, nil
	case "capability_report":
		cap := frame.GetCapability()
		if cap.GetAgentId() == "" {
			return nil, status.Error(codes.InvalidArgument, "capability_report agent_id is required")
		}
		st := s.backend.Store()
		st.AddAgent(store.AgentIdentity{AgentID: cap.GetAgentId(), HostID: cap.GetHostId(), TenantID: cap.GetTenantId(), Version: cap.GetSensor().GetVersion()})
		if err := st.Save(); err != nil {
			return nil, status.Errorf(codes.Internal, "save capability: %v", err)
		}
		return []*controlplanev1.ControlFrame{controlAckFrame(frame, "accepted", "capability accepted", "", false)}, nil
	case "response_ack":
		ack := responseAckFromControl(frame.GetResponseAck())
		if ack.ResponseID == "" {
			return nil, status.Error(codes.InvalidArgument, "response_ack response_id is required")
		}
		tenantID, agentID, err := ackIdentity(frame.GetContext(), ack.TenantID, ack.AgentID)
		if err != nil {
			return nil, err
		}
		ack.TenantID, ack.AgentID = tenantID, agentID
		st := s.backend.Store()
		if _, ok, err := st.AckResponse(ack); err != nil {
			return nil, status.Errorf(codes.Internal, "save response ack: %v", err)
		} else if !ok {
			return nil, status.Error(codes.NotFound, "response command not found")
		}
		return []*controlplanev1.ControlFrame{controlAckFrame(frame, "accepted", "response ack accepted", "", false)}, nil
	case "evidence_pullback_result":
		result := evidencePullbackResultFromControl(frame.GetEvidenceResult())
		if result.RequestID == "" {
			return nil, status.Error(codes.InvalidArgument, "evidence_pullback_result request_id is required")
		}
		st := s.backend.Store()
		req, ok, err := st.GetEvidencePullbackWithError(result.RequestID, result.TenantID, result.AgentID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read evidence pullback request: %v", err)
		}
		if !ok {
			return nil, status.Error(codes.NotFound, "evidence pullback request not found")
		}
		if len(result.Evidence) > 0 {
			evidence := &incidentv1.EvidenceSubgraph{}
			if err := protojson.Unmarshal(result.Evidence, evidence); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "decode evidence pullback evidence: %v", err)
			}
			if _, ok := st.AttachIncidentEvidence(req.IncidentID, store.LabelSelector(req.Labels), evidence); !ok {
				return nil, status.Error(codes.NotFound, "incident for evidence pullback not found")
			}
		}
		if _, ok := st.CompleteEvidencePullback(result); !ok {
			return nil, status.Error(codes.NotFound, "evidence pullback request not found")
		}
		if err := st.Save(); err != nil {
			return nil, status.Errorf(codes.Internal, "save evidence pullback result: %v", err)
		}
		return []*controlplanev1.ControlFrame{controlAckFrame(frame, "accepted", "evidence pullback result accepted", "", false)}, nil
	case "ack":
		if frame.GetAck() == nil {
			return nil, status.Error(codes.InvalidArgument, "ack payload is required")
		}
		st := s.backend.Store()
		ack := controlCommandAckFromControl(frame.GetAck())
		if ack.CommandID == "" {
			return nil, status.Error(codes.InvalidArgument, "ack request_id is required")
		}
		tenantID, agentID, err := ackIdentity(frame.GetContext(), ack.TenantID, ack.AgentID)
		if err != nil {
			return nil, err
		}
		ack.TenantID, ack.AgentID = tenantID, agentID
		if _, ok, err := st.AckControlCommand(ack); err != nil {
			return nil, status.Errorf(codes.Internal, "save control command ack: %v", err)
		} else if !ok && !isHelloPolicyAck(ack.CommandID) {
			return nil, status.Error(codes.NotFound, "control command not found")
		}
		return []*controlplanev1.ControlFrame{controlAckFrame(frame, "accepted", "ack accepted", "", false)}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported control frame type %q", frame.GetType())
	}
}

func isHelloPolicyAck(commandID string) bool {
	return strings.HasPrefix(commandID, "policy-hello-")
}

func ackIdentity(ctx *controlplanev1.RequestContext, payloadTenantID, payloadAgentID string) (string, string, error) {
	tenantID := ctx.GetTenantId()
	if tenantID == "" {
		tenantID = "default"
	}
	agentID := ctx.GetAgentId()
	if agentID == "" {
		return "", "", status.Error(codes.InvalidArgument, "ack context agent_id is required")
	}
	if payloadTenantID != "" && payloadTenantID != tenantID {
		return "", "", status.Error(codes.PermissionDenied, "ack tenant_id does not match frame context")
	}
	if payloadAgentID != "" && payloadAgentID != agentID {
		return "", "", status.Error(codes.PermissionDenied, "ack agent_id does not match frame context")
	}
	return tenantID, agentID, nil
}

func currentPolicyFrame(policy policymodel.Policy) *controlplanev1.CurrentPolicyResponse {
	raw, _ := json.Marshal(policy.EndpointPolicy())
	return &controlplanev1.CurrentPolicyResponse{
		PolicyId:      policy.PolicyID,
		Version:       policy.Version,
		TenantId:      policy.TenantID,
		Scope:         &controlplanev1.Scope{Type: policy.Scope.Type, Selector: policy.Scope.Selector},
		Mode:          policy.Mode,
		EndpointRules: append([]string(nil), policy.EndpointRules...),
		CloudRules:    append([]string(nil), policy.CloudRules...),
		Published:     policy.Published,
		RawJson:       string(raw),
	}
}

func resumeCursorFrame(cursor ResumeCursor) *controlplanev1.ResumeCursor {
	return &controlplanev1.ResumeCursor{
		TenantId:     cursor.TenantID,
		AgentId:      cursor.AgentID,
		SessionId:    cursor.SessionID,
		ResumeCursor: cursor.ResumeCursor,
	}
}

func responseCommandControlFrame(cmd responsemodel.Command) *controlplanev1.ResponseCommand {
	raw, _ := json.Marshal(cmd)
	return &controlplanev1.ResponseCommand{
		ResponseId:        cmd.ResponseID,
		TenantId:          cmd.TenantID,
		AgentId:           cmd.AgentID,
		PolicyId:          cmd.PolicyID,
		PolicyVersion:     cmd.PolicyVersion,
		SignalId:          cmd.SignalID,
		Labels:            cloneLabels(cmd.Labels),
		Scope:             &controlplanev1.ResponseScope{Type: cmd.Scope.Type, Selector: cmd.Scope.Selector},
		Action:            cmd.Action,
		Mode:              cmd.Mode,
		Target:            cmd.Target,
		Reason:            cmd.Reason,
		Status:            cmd.Status,
		Actor:             cmd.Actor,
		ApprovalRequired:  cmd.ApprovalRequired,
		ApprovalStatus:    cmd.ApprovalStatus,
		ApprovalThreshold: cmd.ApprovalThreshold,
		ApprovalRoles:     append([]string(nil), cmd.ApprovalRoles...),
		RawJson:           string(raw),
	}
}

func evidencePullbackControlFrame(req controlmodel.EvidencePullbackRequest) *controlplanev1.EvidencePullbackRequest {
	raw, _ := json.Marshal(req)
	return &controlplanev1.EvidencePullbackRequest{
		RequestId:  req.RequestID,
		TenantId:   req.TenantID,
		AgentId:    req.AgentID,
		IncidentId: req.IncidentID,
		Labels:     cloneLabels(req.Labels),
		Target:     req.Target,
		Reason:     req.Reason,
		Status:     req.Status,
		Actor:      req.Actor,
		RawJson:    string(raw),
	}
}

func controlCommandFrame(cmd controlmodel.ControlCommand, scope *controlplanev1.Scope) (*controlplanev1.ControlFrame, error) {
	ctx := &controlplanev1.RequestContext{TenantId: cmd.TenantID, AgentId: cmd.AgentID, RequestId: cmd.CommandID, Scope: scope}
	frame := &controlplanev1.ControlFrame{
		Type:            cmd.Type,
		RequestId:       cmd.CommandID,
		Context:         ctx,
		ContractVersion: 1,
		PayloadJson:     append([]byte(nil), cmd.PayloadJSON...),
	}
	switch cmd.Type {
	case controlmodel.ControlCommandTypePolicyUpdate:
		policy := policymodel.Policy{
			PolicyID: cmd.PolicyID,
			Version:  cmd.PolicyVersion,
			TenantID: cmd.TenantID,
		}
		if len(cmd.PayloadJSON) > 0 {
			if err := json.Unmarshal(cmd.PayloadJSON, &policy); err != nil {
				return nil, fmt.Errorf("decode policy update payload for command %s: %w", cmd.CommandID, err)
			}
		}
		frame.PolicyUpdate = currentPolicyFrame(policymodel.Normalize(policy))
	case controlmodel.ControlCommandTypeContentUpdate:
		frame.ContentUpdate = &controlplanev1.ApplyContentRequest{
			Context:       ctx,
			ContentJson:   string(cmd.PayloadJSON),
			AllowUnsigned: false,
		}
	default:
		return nil, nil
	}
	return frame, nil
}

func controlCommandAckFromControl(in *controlplanev1.ControlAck) controlmodel.ControlCommandAck {
	if in == nil {
		return controlmodel.ControlCommandAck{}
	}
	return controlmodel.ControlCommandAck{
		CommandID:     in.GetRequestId(),
		TenantID:      in.GetTenantId(),
		AgentID:       in.GetAgentId(),
		Status:        in.GetStatus(),
		Message:       in.GetMessage(),
		PolicyID:      in.GetPolicyId(),
		PolicyVersion: in.GetPolicyVersion(),
		ReportJSON:    in.GetReportJson(),
		ObservedAt:    time.Now().UTC(),
	}
}

func responseAckFromControl(in *controlplanev1.ResponseAck) responsemodel.Ack {
	if in == nil {
		return responsemodel.Ack{}
	}
	return responsemodel.Ack{
		ResponseID:  in.GetResponseId(),
		TenantID:    in.GetTenantId(),
		AgentID:     in.GetAgentId(),
		Accepted:    in.GetAccepted(),
		Unsupported: in.GetUnsupported(),
		ObserveOnly: in.GetObserveOnly(),
		Executed:    in.GetExecuted(),
		Message:     in.GetMessage(),
		ObservedAt:  parseControlTime(in.GetObservedAt()),
	}
}

func evidencePullbackResultFromControl(in *controlplanev1.EvidencePullbackResult) controlmodel.EvidencePullbackResult {
	if in == nil {
		return controlmodel.EvidencePullbackResult{}
	}
	return controlmodel.EvidencePullbackResult{
		RequestID:  in.GetRequestId(),
		TenantID:   in.GetTenantId(),
		AgentID:    in.GetAgentId(),
		OK:         in.GetOk(),
		Message:    in.GetMessage(),
		Evidence:   append([]byte(nil), in.GetEvidenceJson()...),
		ObservedAt: parseControlTime(in.GetObservedAt()),
	}
}

func controlAckFrame(frame *controlplanev1.ControlFrame, statusText, message, code string, retryable bool) *controlplanev1.ControlFrame {
	req := frame.GetContext()
	out := &controlplanev1.ControlFrame{
		Type:            "ack",
		RequestId:       frame.GetRequestId(),
		Context:         req,
		ContractVersion: 1,
		Ack: &controlplanev1.ControlAck{
			RequestId: frame.GetRequestId(),
			TenantId:  req.GetTenantId(),
			AgentId:   req.GetAgentId(),
			Status:    statusText,
			Message:   message,
		},
	}
	if code != "" {
		out.Error = &controlplanev1.ControlError{Code: code, Message: message, Retryable: retryable}
	}
	return out
}

func errorCode(err error) string {
	if st, ok := status.FromError(err); ok {
		return st.Code().String()
	}
	return codes.Unknown.String()
}

func errorRetryable(err error) bool {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded:
			return true
		default:
			return false
		}
	}
	return false
}

func (s *ControlServer) authorized(ctx context.Context) bool {
	token := s.backend.AgentToken()
	if token == "" {
		return true
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, value := range md.Get("x-sysarmor-agent-token") {
		if value == token {
			return true
		}
	}
	for _, value := range md.Get("authorization") {
		if value == "Bearer "+token {
			return true
		}
	}
	return false
}

func agentHealthFromControl(in *controlplanev1.HealthResponse) agenthealth.AgentHealth {
	if in == nil {
		return agenthealth.AgentHealth{}
	}
	return agenthealth.AgentHealth{
		AgentID:       in.GetAgentId(),
		HostID:        in.GetHostId(),
		TenantID:      in.GetTenantId(),
		Scope:         agenthealth.RuntimeScope{Type: in.GetScope().GetType(), Selector: in.GetScope().GetSelector()},
		Status:        in.GetStatus(),
		PolicyID:      in.GetPolicyId(),
		PolicyVersion: in.GetPolicyVersion(),
		PolicyMode:    in.GetPolicyMode(),
		PendingPolicy: agenthealth.PendingPolicyStatus{
			Status:   in.GetPendingPolicy().GetStatus(),
			Source:   in.GetPendingPolicy().GetSource(),
			PolicyID: in.GetPendingPolicy().GetPolicyId(),
			Version:  in.GetPendingPolicy().GetVersion(),
			Digest:   in.GetPendingPolicy().GetDigest(),
		},
		UptimeSeconds: in.GetUptimeSeconds(),
		Capability:    sensorCapabilityFromControl(in.GetCapability()),
		Sensor: agenthealth.SensorHealth{
			Backend:        in.GetSensor().GetBackend(),
			Installed:      in.GetSensor().GetInstalled(),
			Running:        in.GetSensor().GetRunning(),
			Version:        in.GetSensor().GetVersion(),
			PolicyLoaded:   in.GetSensor().GetPolicyLoaded(),
			EventsSeen:     in.GetSensor().GetEventsSeen(),
			EventsDropped:  in.GetSensor().GetEventsDropped(),
			ParseErrors:    in.GetSensor().GetParseErrors(),
			RestartCount:   in.GetSensor().GetRestartCount(),
			LastEventAt:    parseControlTime(in.GetSensor().GetLastEventAt()),
			LastExitReason: in.GetSensor().GetLastExitReason(),
			LastError:      in.GetSensor().GetLastError(),
		},
		TelemetryBus: agenthealth.TelemetryBusHealth{
			EventCapacity:     in.GetTelemetryBus().GetEventCapacity(),
			EventBuffered:     in.GetTelemetryBus().GetEventBuffered(),
			EventDropped:      in.GetTelemetryBus().GetEventDropped(),
			EventSubscribers:  in.GetTelemetryBus().GetEventSubscribers(),
			SignalCapacity:    in.GetTelemetryBus().GetSignalCapacity(),
			SignalBuffered:    in.GetTelemetryBus().GetSignalBuffered(),
			SignalDropped:     in.GetTelemetryBus().GetSignalDropped(),
			SignalSubscribers: in.GetTelemetryBus().GetSignalSubscribers(),
		},
		TelemetryBatcher: agenthealth.TelemetryBatcherHealth{
			PendingEvents:     in.GetTelemetryBatcher().GetPendingEvents(),
			PendingSignals:    in.GetTelemetryBatcher().GetPendingSignals(),
			QueuedBatches:     in.GetTelemetryBatcher().GetQueuedBatches(),
			QueueCapacity:     in.GetTelemetryBatcher().GetQueueCapacity(),
			DroppedBatches:    in.GetTelemetryBatcher().GetDroppedBatches(),
			DroppedEvents:     in.GetTelemetryBatcher().GetDroppedEvents(),
			DroppedSignals:    in.GetTelemetryBatcher().GetDroppedSignals(),
			FlushedBatches:    in.GetTelemetryBatcher().GetFlushedBatches(),
			FlushedEvents:     in.GetTelemetryBatcher().GetFlushedEvents(),
			FlushedSignals:    in.GetTelemetryBatcher().GetFlushedSignals(),
			PendingBytes:      in.GetTelemetryBatcher().GetPendingBytes(),
			MaxBytes:          in.GetTelemetryBatcher().GetMaxBytes(),
			FlushedByCount:    in.GetTelemetryBatcher().GetFlushedByCount(),
			FlushedByBytes:    in.GetTelemetryBatcher().GetFlushedByBytes(),
			FlushedByInterval: in.GetTelemetryBatcher().GetFlushedByInterval(),
			FlushedByShutdown: in.GetTelemetryBatcher().GetFlushedByShutdown(),
			LastFlushReason:   in.GetTelemetryBatcher().GetLastFlushReason(),
			Closed:            in.GetTelemetryBatcher().GetClosed(),
			LastError:         in.GetTelemetryBatcher().GetLastError(),
		},
		TelemetrySender: agenthealth.TelemetrySenderHealth{
			SentBatches:     in.GetTelemetrySender().GetSentBatches(),
			SentEvents:      in.GetTelemetrySender().GetSentEvents(),
			SentSignals:     in.GetTelemetrySender().GetSentSignals(),
			RejectedBatches: in.GetTelemetrySender().GetRejectedBatches(),
			RetriedBatches:  in.GetTelemetrySender().GetRetriedBatches(),
			Drained:         in.GetTelemetrySender().GetDrained(),
			LastError:       in.GetTelemetrySender().GetLastError(),
		},
		CEP: agenthealth.CEPHealth{
			ActiveGroups:     in.GetCep().GetActiveGroups(),
			EvictedGroups:    in.GetCep().GetEvictedGroups(),
			ExpiredGroups:    in.GetCep().GetExpiredGroups(),
			DroppedEventRefs: in.GetCep().GetDroppedEventRefs(),
			EvalErrors:       in.GetCep().GetEvalErrors(),
			EmittedSignals:   in.GetCep().GetEmittedSignals(),
			Degraded:         in.GetCep().GetDegraded(),
		},
		ObservedAt: parseControlTime(in.GetObservedAt()),
	}
}

func sensorCapabilityFromControl(in *controlplanev1.SensorCapability) agenthealth.SensorCapability {
	if in == nil {
		return agenthealth.SensorCapability{}
	}
	return agenthealth.SensorCapability{
		Backend:         in.GetBackend(),
		Version:         in.GetVersion(),
		SupportsExec:    in.GetSupportsExec(),
		SupportsConnect: in.GetSupportsConnect(),
		SupportsFile:    in.GetSupportsFile(),
		SupportsEnforce: in.GetSupportsEnforce(),
		SupportsHealth:  in.GetSupportsHealth(),
		KernelRelease:   in.GetKernelRelease(),
		BTFAvailable:    in.GetBtfAvailable(),
		BPFFSAvailable:  in.GetBpffsAvailable(),
	}
}

func parseControlTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, value)
	return t
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		out[k] = v
	}
	return out
}
