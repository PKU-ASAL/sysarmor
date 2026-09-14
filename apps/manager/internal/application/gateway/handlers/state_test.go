package handlers

import (
	"context"
	domaingateway "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/gateway"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
	"testing"
)

type fakeWriter struct{ called string }

func (w *fakeWriter) RecordHealth(context.Context, domainidentity.Health) error {
	w.called = "health"
	return nil
}
func (w *fakeWriter) RecordCapability(context.Context, domaingateway.Capability) error {
	w.called = "capability"
	return nil
}
func (w *fakeWriter) AckResponse(context.Context, domaingateway.Ack) error {
	w.called = "response"
	return nil
}
func (w *fakeWriter) AckCommand(context.Context, domaingateway.Ack) error {
	w.called = "command"
	return nil
}
func (w *fakeWriter) CompleteEvidence(context.Context, domaingateway.EvidenceResult) error {
	w.called = "evidence"
	return nil
}

func TestStateHandlersDelegateByFrameType(t *testing.T) {
	tests := []struct {
		kind, called string
		payload      any
	}{
		{"health_report", "health", domainidentity.Health{}}, {"capability_report", "capability", domaingateway.Capability{}}, {"response_ack", "response", domaingateway.Ack{}}, {"ack", "command", domaingateway.Ack{}}, {"evidence_pullback_result", "evidence", domaingateway.EvidenceResult{}},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			writer := &fakeWriter{}
			result, err := NewStateHandler(test.kind, writer).Handle(context.Background(), ports.ControlFrame{Type: test.kind, Payload: test.payload})
			if err != nil || writer.called != test.called || len(result.Frames) != 1 {
				t.Fatalf("called=%q result=%+v err=%v", writer.called, result, err)
			}
		})
	}
}

func TestStateHandlerDelegatesSessionPolicyAckAsCommand(t *testing.T) {
	writer := &fakeWriter{}
	result, err := NewStateHandler("ack", writer).Handle(context.Background(), ports.ControlFrame{
		Type: "ack", Payload: domaingateway.Ack{ID: "policy-hello-20260811T045506Z", Status: "applied"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if writer.called != "command" || len(result.Frames) != 1 || result.Frames[0].Type != "ack" {
		t.Fatalf("called=%q result=%+v", writer.called, result)
	}
}
