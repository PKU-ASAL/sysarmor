package handlers

import (
	"context"
	"testing"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestHelloReturnsPolicyResumeAndPendingMessages(t *testing.T) {
	repository := &helloRepositoryStub{result: domaingateway.OpenSession{
		TenantID: "tenant-a", AgentID: "agent-a", SessionID: "session-a", ResumeCursor: "batch-7",
		PolicyDocument: []byte(`{"policy_id":"policy-a"}`),
		Messages:       []domaingateway.Message{{Type: "response_command", ID: "response-a", Document: []byte(`{"response_id":"response-a"}`)}},
	}}
	handler := NewHelloHandler(gatewayapp.NewOpenSessionService(repository, helloDeliveryStub{}))
	frame := ports.ControlFrame{TenantID: "tenant-a", AgentID: "agent-a", RequestID: "hello-a", Payload: domaingateway.Hello{ScopeType: "host", ScopeSelector: "host-a"}}
	result, err := handler.Handle(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Frames) != 3 || result.Frames[0].Type != "policy_update" || result.Frames[1].Type != "resume" || result.Frames[2].RequestID != "response-a" {
		t.Fatalf("frames = %+v", result.Frames)
	}
	if got := repository.args; len(got) != 4 || got[2] != "host" || got[3] != "host-a" {
		t.Fatalf("Open() args = %v", got)
	}
}

type helloDeliveryStub struct{}

func (helloDeliveryStub) MarkSent(context.Context, string, string, string) error { return nil }

type helloRepositoryStub struct {
	result domaingateway.OpenSession
	args   []string
}

func (stub *helloRepositoryStub) Open(_ context.Context, tenantID, agentID, scopeType, scopeSelector string) (domaingateway.OpenSession, error) {
	stub.args = []string{tenantID, agentID, scopeType, scopeSelector}
	return stub.result, nil
}
