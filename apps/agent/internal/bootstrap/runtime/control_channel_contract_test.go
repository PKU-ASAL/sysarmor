package runtime

import (
	"fmt"
	"net"
	"testing"

	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"google.golang.org/grpc"
)

type healthControlContractServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	received chan *controlplanev1.HealthResponse
}

func (s *healthControlContractServer) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	hello, err := receiveHello(stream)
	if err != nil {
		return err
	}
	if err := sendHelloFrames(stream, hello, true); err != nil {
		return err
	}
	frame, err := stream.Recv()
	if err != nil {
		return err
	}
	if frame.GetType() != "health_report" {
		return fmt.Errorf("frame type = %q, want health_report", frame.GetType())
	}
	s.received <- frame.GetHealth()
	return stream.Send(&controlplanev1.ControlFrame{
		Type: "ack", RequestId: frame.GetRequestId(), ContractVersion: 1, Sequence: 3,
		Ack: &controlplanev1.ControlAck{RequestId: frame.GetRequestId(), Status: "accepted"},
	})
}

type responseControlObservation struct {
	ack        *controlplanev1.ResponseAck
	capability *controlplanev1.CapabilityResponse
}

type responseControlContractServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	observed chan responseControlObservation
}

func (s *responseControlContractServer) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	hello, err := receiveHello(stream)
	if err != nil {
		return err
	}
	if err := sendHelloFrames(stream, hello, false); err != nil {
		return err
	}
	if err := stream.Send(responseCommandFrame(hello)); err != nil {
		return err
	}
	observation := responseControlObservation{}
	for observation.ack == nil || observation.capability == nil {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		switch frame.GetType() {
		case "response_ack":
			observation.ack = frame.GetResponseAck()
		case "capability_report":
			observation.capability = frame.GetCapability()
		}
	}
	s.observed <- observation
	<-stream.Context().Done()
	return stream.Context().Err()
}

func startControlContractServer(t *testing.T, server controlplanev1.AgentControlPlaneServiceServer) string {
	t.Helper()
	grpcServer := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(grpcServer, server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	return listener.Addr().String()
}

func receiveHello(stream controlplanev1.AgentControlPlaneService_ConnectServer) (*controlplanev1.ControlFrame, error) {
	hello, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	if hello.GetType() != "hello" {
		return nil, fmt.Errorf("first frame type = %q, want hello", hello.GetType())
	}
	return hello, nil
}

func sendHelloFrames(stream controlplanev1.AgentControlPlaneService_ConnectServer, hello *controlplanev1.ControlFrame, includePolicy bool) error {
	sequence := uint64(1)
	if includePolicy {
		if err := stream.Send(controlFrame(hello, "policy_update", sequence)); err != nil {
			return err
		}
		sequence++
	}
	return stream.Send(controlFrame(hello, "resume", sequence))
}

func controlFrame(hello *controlplanev1.ControlFrame, frameType string, sequence uint64) *controlplanev1.ControlFrame {
	frame := &controlplanev1.ControlFrame{
		Type: frameType, RequestId: hello.GetRequestId(), ContractVersion: 1, Sequence: sequence,
		Context: hello.GetContext(),
	}
	if frameType == "policy_update" {
		frame.PolicyUpdate = &controlplanev1.CurrentPolicyResponse{}
	} else {
		frame.Resume = &controlplanev1.ResumeCursor{}
	}
	return frame
}

func responseCommandFrame(hello *controlplanev1.ControlFrame) *controlplanev1.ControlFrame {
	return &controlplanev1.ControlFrame{
		Type: "response_command", RequestId: "resp-runner-long", ContractVersion: 1, Sequence: 2,
		Context: hello.GetContext(),
		ResponseCommand: &controlplanev1.ResponseCommand{
			ResponseId: "resp-runner-long", TenantId: "default", AgentId: "agent-runner-long",
			PolicyId: policymodel.DefaultPolicyID, PolicyVersion: policymodel.DefaultPolicyVersion,
			Action: "collect", Target: "process:p1", Status: "pending",
		},
	}
}
