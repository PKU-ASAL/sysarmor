package remoteapi

import (
	"context"
	"strings"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"google.golang.org/protobuf/proto"
)

type recordingPolicyController struct {
	command agentcontrol.PolicyCommand
	status  string
	message string
}

func (r *recordingPolicyController) ApplyPolicy(_ context.Context, command agentcontrol.PolicyCommand) agentcontrol.Result {
	r.command = command
	status := r.status
	if status == "" {
		status = "applied"
	}
	return agentcontrol.Result{RequestID: command.Context.RequestID, Status: status, Message: r.message}
}

func (*recordingPolicyController) CurrentPolicy(context.Context) (agentcontrol.PolicySnapshot, error) {
	return agentcontrol.PolicySnapshot{}, nil
}

type recordingContentController struct {
	command agentcontrol.ContentCommand
}

func (r *recordingContentController) ApplyContent(_ context.Context, command agentcontrol.ContentCommand) agentcontrol.Result {
	r.command = command
	return agentcontrol.Result{RequestID: command.Context.RequestID, Status: "applied"}
}

func (*recordingContentController) ListContent(context.Context, string) ([]agentcontent.Record, error) {
	return nil, nil
}

func (*recordingContentController) GetContent(context.Context, string) (agentcontent.Record, bool, error) {
	return agentcontent.Record{}, false, nil
}

func TestDispatcherBuildsManagedPolicyCommand(t *testing.T) {
	controller := &recordingPolicyController{}
	dispatcher := NewDispatcher(Dependencies{Policy: controller}, nil)
	result, handled, err := dispatcher.Dispatch(t.Context(), Identity{TenantID: "tenant-a", AgentID: "agent-a"}, &controlplanev1.ControlFrame{
		Type: "policy_update", RequestId: "request-a",
		Context: &controlplanev1.RequestContext{
			TenantId: "tenant-a", AgentId: "agent-a",
			Scope: &controlplanev1.Scope{Type: "container", Selector: "container-a"},
		},
		PolicyUpdate: &controlplanev1.CurrentPolicyResponse{RawJson: `{"policy_id":"policy-a"}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !handled || controller.command.Source != agentcontrol.PolicySourceManaged || result.Status != "applied" || result.TenantID != "tenant-a" || result.AgentID != "agent-a" ||
		controller.command.Context.Scope == nil || controller.command.Context.Scope.Type != "container" || controller.command.Context.Scope.Selector != "container-a" {
		t.Fatalf("command=%+v result=%+v handled=%t", controller.command, result, handled)
	}
}

func TestDispatcherAppliesHandshakePolicySnapshot(t *testing.T) {
	controller := &recordingPolicyController{}
	dispatcher := NewDispatcher(Dependencies{Policy: controller}, nil)
	identity := Identity{TenantID: "tenant-a", AgentID: "agent-a"}
	frame := &controlplanev1.ControlFrame{
		Type:      "policy_update",
		RequestId: "policy-hello-a",
		Context:   &controlplanev1.RequestContext{TenantId: "tenant-a", AgentId: "agent-a"},
		PolicyUpdate: &controlplanev1.CurrentPolicyResponse{
			RawJson: `{"policy_id":"policy-a"}`,
		},
	}

	if err := dispatcher.HandleSnapshot(t.Context(), identity, frame); err != nil {
		t.Fatal(err)
	}
	if controller.command.Context.RequestID != "policy-hello-a" || controller.command.Context.TenantID != "tenant-a" || controller.command.Context.AgentID != "agent-a" {
		t.Fatalf("command = %+v", controller.command)
	}
}

func TestDispatcherReportsRejectedHandshakePolicySnapshot(t *testing.T) {
	controller := &recordingPolicyController{status: "rejected", message: "invalid policy"}
	dispatcher := NewDispatcher(Dependencies{Policy: controller}, nil)
	frame := &controlplanev1.ControlFrame{
		Type: "policy_update", RequestId: "policy-hello-a",
		PolicyUpdate: &controlplanev1.CurrentPolicyResponse{RawJson: `{}`},
	}

	err := dispatcher.HandleSnapshot(t.Context(), Identity{}, frame)

	if err == nil || !strings.Contains(err.Error(), "invalid policy") {
		t.Fatalf("err = %v", err)
	}
}

func TestDispatcherBuildsManagedContentCommandWithoutMutatingFrame(t *testing.T) {
	controller := &recordingContentController{}
	dispatcher := NewDispatcher(Dependencies{Content: controller}, nil)
	frame := &controlplanev1.ControlFrame{
		Type: "content_update", RequestId: "request-a",
		Context: &controlplanev1.RequestContext{TenantId: "tenant-a", AgentId: "agent-a"},
		ContentUpdate: &controlplanev1.ApplyContentRequest{
			ContentJson: `{"content_id":"content-a"}`,
			DryRun:      true, AllowUnsigned: true,
		},
	}
	wantFrame := proto.Clone(frame).(*controlplanev1.ControlFrame)

	result, handled, err := dispatcher.Dispatch(t.Context(), Identity{TenantID: "tenant-a", AgentID: "agent-a"}, frame)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || controller.command.Source != agentcontrol.PolicySourceManaged || controller.command.Context.RequestID != "request-a" || result.TenantID != "tenant-a" || result.AgentID != "agent-a" {
		t.Fatalf("command=%+v result=%+v handled=%t", controller.command, result, handled)
	}
	if !proto.Equal(frame, wantFrame) {
		t.Fatalf("dispatcher mutated input frame: got=%v want=%v", frame, wantFrame)
	}
}

func TestControlAckPreservesControlResult(t *testing.T) {
	result := agentcontrol.Result{
		RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a",
		Status: "applied", Message: "ok", PolicyID: "policy-a", Version: 7,
		Details: []string{"detail-a"}, ReportJSON: `{"status":"ok"}`,
		Sections: []agentcontrol.SectionResult{{
			Name: "detection", Status: "applied", Message: "ok",
			RequiresRestart: true, Details: []string{"section-detail"}, ReportJSON: `{"restarted":true}`,
		}},
	}
	want := &controlplanev1.ControlAck{
		RequestId: "request-a", TenantId: "tenant-a", AgentId: "agent-a",
		Status: "applied", Message: "ok", PolicyId: "policy-a", PolicyVersion: 7,
		Details: []string{"detail-a"}, ReportJson: `{"status":"ok"}`,
		Sections: []*controlplanev1.AppliedSection{{
			Name: "detection", Status: "applied", Message: "ok",
			RequiresRestart: true, Details: []string{"section-detail"}, ReportJson: `{"restarted":true}`,
		}},
	}
	if got := controlAck(result); !proto.Equal(got, want) {
		t.Fatalf("controlAck()=%v want=%v", got, want)
	}
}
