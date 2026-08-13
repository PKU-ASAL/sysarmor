package remoteapi

import (
	"context"
	"fmt"
	"io"

	appresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/response"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

type Identity struct {
	TenantID string
	AgentID  string
}

type Dependencies struct {
	Policy   agentcontrol.PolicyController
	Content  agentcontrol.ContentController
	Response appresponse.Controller
}

type Dispatcher struct {
	deps Dependencies
	out  io.Writer
}

func NewDispatcher(deps Dependencies, out io.Writer) *Dispatcher {
	return &Dispatcher{deps: deps, out: out}
}

func (d *Dispatcher) Dispatch(ctx context.Context, identity Identity, frame *controlplanev1.ControlFrame) (agentcontrol.Result, bool, error) {
	switch frame.GetType() {
	case "policy_update":
		if d.deps.Policy == nil {
			return agentcontrol.Result{}, true, fmt.Errorf("remote api policy controller is unavailable")
		}
		result := d.deps.Policy.ApplyPolicy(ctx, policyCommand(frame))
		return bindResultToIdentity(result, identity), true, nil
	case "content_update":
		if d.deps.Content == nil {
			return agentcontrol.Result{}, true, fmt.Errorf("remote api content controller is unavailable")
		}
		result := d.deps.Content.ApplyContent(ctx, contentCommand(frame))
		return bindResultToIdentity(result, identity), true, nil
	default:
		return agentcontrol.Result{}, false, nil
	}
}

func (d *Dispatcher) Handle(ctx context.Context, session *ControlChannel, identity Identity, frame *controlplanev1.ControlFrame) error {
	if result, handled, err := d.Dispatch(ctx, identity, frame); err != nil {
		return err
	} else if handled {
		if err := session.SendControlAck(ctx, controlAck(result)); err != nil {
			return err
		}
		d.logControlResult(frame.GetType(), result)
		return nil
	}
	switch frame.GetType() {
	case "ack":
		if frame.GetAck().GetStatus() == "rejected" {
			return fmt.Errorf("control channel request rejected: %s", frame.GetAck().GetMessage())
		}
	case "resume":
		if d.out != nil {
			fmt.Fprintf(d.out, "agent control resume cursor ignored by telemetry data plane: %s\n", frame.GetResume().GetResumeCursor())
		}
	case "response_command":
		return d.handleResponse(ctx, session, frame)
	case "evidence_pullback":
		return d.handleEvidence(ctx, session, frame)
	}
	return nil
}

func (d *Dispatcher) HandleSnapshot(ctx context.Context, identity Identity, frame *controlplanev1.ControlFrame) error {
	if frame.GetType() != "policy_update" {
		return fmt.Errorf("unsupported control snapshot type %q", frame.GetType())
	}
	result, _, err := d.Dispatch(ctx, identity, frame)
	if err != nil {
		return err
	}
	if result.Status == "rejected" {
		return fmt.Errorf("control policy snapshot rejected: %s", result.Message)
	}
	return nil
}

func (d *Dispatcher) handleResponse(ctx context.Context, session *ControlChannel, frame *controlplanev1.ControlFrame) error {
	if d.deps.Response == nil {
		return fmt.Errorf("remote api response controller is unavailable")
	}
	cmd, err := responseCommand(frame.GetResponseCommand())
	if err != nil {
		return err
	}
	ack := d.deps.Response.Execute(ctx, cmd)
	if err := session.SendResponseAck(ctx, ack); err != nil {
		return err
	}
	if d.out != nil {
		fmt.Fprintf(d.out, "agent control response ack: response=%s action=%s observe_only=%t unsupported=%t executed=%t\n", ack.ResponseID, cmd.Action, ack.ObserveOnly, ack.Unsupported, ack.Executed)
	}
	return nil
}

func (d *Dispatcher) handleEvidence(ctx context.Context, session *ControlChannel, frame *controlplanev1.ControlFrame) error {
	if d.deps.Response == nil {
		return fmt.Errorf("remote api response controller is unavailable")
	}
	req, err := evidencePullback(frame.GetEvidencePullback())
	if err != nil {
		return err
	}
	result := d.deps.Response.CollectEvidence(ctx, req)
	if err := session.SendEvidenceResult(ctx, result); err != nil {
		return err
	}
	if d.out != nil {
		fmt.Fprintf(d.out, "agent control evidence pullback result: request=%s ok=%t message=%q\n", result.RequestID, result.OK, result.Message)
	}
	return nil
}

func (d *Dispatcher) logControlResult(frameType string, result agentcontrol.Result) {
	if d.out == nil {
		return
	}
	label := "content update"
	if frameType == "policy_update" {
		label = "policy update"
	}
	fmt.Fprintf(d.out, "agent control %s ack: request=%s status=%s message=%q\n", label, result.RequestID, result.Status, result.Message)
}

func bindResultToIdentity(result agentcontrol.Result, identity Identity) agentcontrol.Result {
	result.TenantID = identity.TenantID
	result.AgentID = identity.AgentID
	return result
}
