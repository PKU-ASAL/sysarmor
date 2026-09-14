package gateway

import (
	"context"
	"testing"

	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
)

type controlMessageRepositoryStub struct {
	messages []domaingateway.Message
	args     []string
}

func (stub *controlMessageRepositoryStub) Pending(_ context.Context, tenantID, agentID string) ([]domaingateway.Message, error) {
	stub.args = []string{tenantID, agentID}
	return stub.messages, nil
}

func TestPendingControlPullsAndMarksCommandsSent(t *testing.T) {
	repository := &controlMessageRepositoryStub{messages: []domaingateway.Message{
		{Type: "control_command", ID: "command-a"},
		{Type: "evidence_pullback", ID: "evidence-a"},
	}}
	delivery := &deliveryStub{}
	service := NewPendingControlService(repository, delivery)

	messages, err := service.Pull(context.Background(), "tenant-a", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || len(repository.args) != 2 {
		t.Fatalf("messages=%+v repository args=%v", messages, repository.args)
	}
	if len(delivery.commandIDs) != 1 || delivery.commandIDs[0] != "command-a" {
		t.Fatalf("marked commands = %v", delivery.commandIDs)
	}
}
