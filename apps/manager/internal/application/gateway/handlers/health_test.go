package handlers

import (
	"context"
	"testing"

	gatewayapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/gateway"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type healthMessageRepositoryStub struct{}

func (healthMessageRepositoryStub) Pending(context.Context, string, string) ([]domaingateway.Message, error) {
	return []domaingateway.Message{{Type: "control_command", ID: "command-a", Document: []byte(`{"type":"policy_update"}`)}}, nil
}

func TestHealthReturnsAckAndPendingControlMessages(t *testing.T) {
	pending := gatewayapp.NewPendingControlService(healthMessageRepositoryStub{}, helloDeliveryStub{})
	handler := NewHealthHandler(&fakeWriter{}, pending)
	result, err := handler.Handle(context.Background(), ports.ControlFrame{
		TenantID: "tenant-a", AgentID: "agent-a", RequestID: "health-a",
		Type: "health_report", Payload: domainidentity.Health{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Frames) != 2 || result.Frames[0].Type != "ack" || result.Frames[1].RequestID != "command-a" {
		t.Fatalf("frames = %+v", result.Frames)
	}
}
