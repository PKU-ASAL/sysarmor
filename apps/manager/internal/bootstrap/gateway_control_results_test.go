package bootstrap

import (
	"context"
	"testing"
	"time"

	responseapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/response"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainresponse "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/response"
)

func TestGatewayResponseAckUsesResponseApplication(t *testing.T) {
	responses := &gatewayResponseResultsStub{}
	writer := gatewayControlStateWriter{responses: responses}
	observedAt := time.Unix(100, 0).UTC()
	err := writer.AckResponse(context.Background(), domaingateway.Ack{
		TenantID: "tenant-a", AgentID: "agent-a", ID: "response-a", Accepted: true,
		Unsupported: false, ObserveOnly: true, Executed: false, Message: "observed", ObservedAt: observedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if responses.command.TenantID != "tenant-a" || responses.command.ResponseID != "response-a" ||
		!responses.command.Accepted || !responses.command.ObserveOnly || responses.command.ObservedAt != observedAt {
		t.Fatalf("command=%+v", responses.command)
	}
}

type gatewayResponseResultsStub struct {
	command responseapp.AcknowledgeCommand
}

func (stub *gatewayResponseResultsStub) Acknowledge(_ context.Context, command responseapp.AcknowledgeCommand) (domainresponse.Acknowledged, error) {
	stub.command = command
	return domainresponse.Acknowledged{}, nil
}
