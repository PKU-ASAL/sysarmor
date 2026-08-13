package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestMapIncomingHelloIncludesScope(t *testing.T) {
	frame := &controlplanev1.ControlFrame{
		Type: "hello", RequestId: "hello-a", Sequence: 1, ContractVersion: 1,
		Context: &controlplanev1.RequestContext{TenantId: "tenant-a", AgentId: "agent-a", Scope: &controlplanev1.Scope{Type: "host", Selector: "host-a"}},
	}
	mapped, err := mapIncoming(frame, "connection-a")
	if err != nil {
		t.Fatal(err)
	}
	hello, ok := mapped.Payload.(domaingateway.Hello)
	if !ok || hello.ScopeType != "host" || hello.ScopeSelector != "host-a" || mapped.SessionID != "connection-a" {
		t.Fatalf("mapped = %+v", mapped)
	}
}

func TestRevokeEnrollmentRequiresMTLSIdentity(t *testing.T) {
	server := NewServer(nil, nil, "", gatewayapp.NewRevokeEnrollmentService(&controlRevocationStub{}))
	_, err := server.RevokeEnrollment(context.Background(), &controlplanev1.RevokeEnrollmentRequest{TenantId: "tenant-a", AgentId: "agent-a"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("RevokeEnrollment() error = %v", err)
	}
}

func TestRevokeEnrollmentMapsApplicationResult(t *testing.T) {
	repository := &controlRevocationStub{certificate: domaingateway.Certificate{TenantID: "tenant-a", AgentID: "agent-a", EnrollmentID: "enroll-a", Serial: "42", Protocol: "legacy_mtls"}, result: domaingateway.Revocation{ReceiptID: "receipt-a"}}
	server := NewServer(nil, nil, "", gatewayapp.NewRevokeEnrollmentService(repository))
	uri, _ := url.Parse("spiffe://sysarmor/tenant/tenant-a/agent/agent-a")
	certificate := &x509.Certificate{SerialNumber: big.NewInt(42), URIs: []*url.URL{uri}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}}})
	response, err := server.RevokeEnrollment(ctx, &controlplanev1.RevokeEnrollmentRequest{TenantId: "tenant-a", AgentId: "agent-a"})
	if err != nil || response.GetReceiptId() != "receipt-a" {
		t.Fatalf("response = %+v, err = %v", response, err)
	}
}

type controlRevocationStub struct {
	certificate domaingateway.Certificate
	result      domaingateway.Revocation
}

func (stub *controlRevocationStub) Certificate(context.Context, string, string) (domaingateway.Certificate, bool, error) {
	return stub.certificate, stub.certificate.Serial != "", nil
}

func (stub *controlRevocationStub) Revoke(context.Context, domaingateway.RevokeEnrollment) (domaingateway.Revocation, error) {
	return stub.result, nil
}

func TestMapReplyBuildsSessionFrames(t *testing.T) {
	request := controlRequest()
	tests := []struct {
		name  string
		reply ports.ControlFrame
		check func(*controlplanev1.ControlFrame) bool
	}{
		{"policy", ports.ControlFrame{Type: "policy_update", RequestID: "policy-a", Payload: []byte(`{"policy_id":"policy-a","version":2,"tenant_id":"tenant-a","published":true}`)}, func(frame *controlplanev1.ControlFrame) bool {
			return frame.GetPolicyUpdate().GetPolicyId() == "policy-a" && frame.GetPolicyUpdate().GetRawJson() != ""
		}},
		{"resume", ports.ControlFrame{Type: "resume", Payload: domaingateway.OpenSession{TenantID: "tenant-a", AgentID: "agent-a", SessionID: "session-a", ResumeCursor: "batch-7"}}, func(frame *controlplanev1.ControlFrame) bool { return frame.GetResume().GetResumeCursor() == "batch-7" }},
		{"response", ports.ControlFrame{Type: "response_command", RequestID: "response-a", Payload: domaingateway.Message{Document: []byte(`{"response_id":"response-a","tenant_id":"tenant-a","agent_id":"agent-a"}`)}}, func(frame *controlplanev1.ControlFrame) bool {
			return frame.GetResponseCommand().GetResponseId() == "response-a"
		}},
		{"evidence", ports.ControlFrame{Type: "evidence_pullback", RequestID: "evidence-a", Payload: domaingateway.Message{Document: []byte(`{"request_id":"evidence-a","tenant_id":"tenant-a","agent_id":"agent-a"}`)}}, func(frame *controlplanev1.ControlFrame) bool {
			return frame.GetEvidencePullback().GetRequestId() == "evidence-a"
		}},
		{"control command", ports.ControlFrame{Type: "control_command", RequestID: "command-a", Payload: domaingateway.Message{Document: []byte(`{"command_id":"command-a","type":"policy_update","payload_json":{"policy_id":"policy-a","version":3,"tenant_id":"tenant-a","published":true}}`)}}, func(frame *controlplanev1.ControlFrame) bool {
			return frame.GetType() == "policy_update" && frame.GetPolicyUpdate().GetPolicyId() == "policy-a"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frame, err := mapReply(request, test.reply)
			if err != nil || !test.check(frame) {
				t.Fatalf("frame = %+v, err = %v", frame, err)
			}
		})
	}
}

func TestMapReplyPreservesCompletePolicyDocument(t *testing.T) {
	raw := []byte(`{"policy_id":"default-edr-policy","version":1,"collection":{"observe_only":true},"detection":{"mode":"observe"}}`)
	frame, err := mapReply(controlRequest(), ports.ControlFrame{Type: "policy_update", Payload: raw})
	if err != nil {
		t.Fatal(err)
	}
	if frame.GetPolicyUpdate().GetPolicyId() != "default-edr-policy" || frame.GetPolicyUpdate().GetRawJson() != string(raw) {
		t.Fatalf("policy update = %+v", frame.GetPolicyUpdate())
	}
}

func controlRequest() *controlplanev1.ControlFrame {
	return &controlplanev1.ControlFrame{Type: "hello", RequestId: "hello-a", Context: &controlplanev1.RequestContext{TenantId: "tenant-a", AgentId: "agent-a"}}
}
