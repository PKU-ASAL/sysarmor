package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/remoteapi"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

func (r *TransportRuntime) runControlFlow(ctx context.Context) {
	runner := r.runner
	backoff := runner.Config.Local.Export.RetryInitial
	if backoff <= 0 {
		backoff = time.Second
	}
	maxBackoff := runner.Config.Local.Export.RetryMax
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	for {
		if err := r.RunControlChannel(ctx); err != nil && ctx.Err() == nil && runner.Out != nil {
			fmt.Fprintf(runner.Out, "agent control channel disconnected: %v\n", err)
		}
		if ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (r *TransportRuntime) RunControlChannel(ctx context.Context) error {
	runner := r.runner
	identity := runner.currentIdentity()
	return r.runControlChannel(ctx, runner.Config.Manager.Address, runner.Config.Agent.Token, runner.managerTLS(), identity)
}

func (r *TransportRuntime) runControlChannel(ctx context.Context, manager, token string, tlsCfg tlsconfig.ClientConfig, identity runtimeIdentity) error {
	runner := r.runner
	connectCtx, cancel := context.WithTimeout(ctx, runner.Config.Local.Export.RequestTimeout)
	defer cancel()
	session := remoteapi.NewControlChannel(manager, token, tlsCfg)
	if err := session.OpenSession(connectCtx, ctx); err != nil {
		return err
	}
	defer session.Close()
	frames, err := session.Hello(connectCtx, identity.TenantID, identity.AgentID, r.scopeType, r.scopeSelector)
	if err != nil {
		return err
	}
	dispatcher := remoteapi.NewDispatcher(remoteapi.Dependencies{
		Policy:   newApplicationPolicyController(runner, r.sensor, r.batcher),
		Content:  agentcontrol.NewContentController(newContentRuntime(runner)),
		Response: agentcontrol.NewResponseController(newResponseRuntime(runner)),
	}, runner.Out)
	remoteIdentity := remoteapi.Identity{TenantID: identity.TenantID, AgentID: identity.AgentID}
	for _, frame := range frames {
		if err := dispatcher.Handle(ctx, session, remoteIdentity, frame); err != nil {
			return err
		}
	}
	health, err := runner.collectHealth(ctx, r.sensor, r.bus, r.batcher, r.sender, r.startedAt)
	if err == nil {
		health = bindHealthToSession(health, identity)
		if err := session.SendHealth(ctx, healthResponse(health)); err != nil {
			return err
		}
		if err := session.SendCapability(ctx, remoteCapabilityResponse(health)); err != nil {
			return err
		}
	}
	recvCh := make(chan *controlplanev1.ControlFrame, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			frame, err := session.Recv()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case recvCh <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()
	interval := runner.Config.Health.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("control channel closed")
			}
			return err
		case frame := <-recvCh:
			if err := dispatcher.Handle(ctx, session, remoteIdentity, frame); err != nil {
				return err
			}
		case <-ticker.C:
			health, err := runner.collectHealth(ctx, r.sensor, r.bus, r.batcher, r.sender, r.startedAt)
			if err != nil {
				return err
			}
			health = bindHealthToSession(health, identity)
			if err := session.SendHealth(ctx, healthResponse(health)); err != nil {
				return err
			}
			if err := session.SendCapability(ctx, remoteCapabilityResponse(health)); err != nil {
				return err
			}
		}
	}
}

func (r *TransportRuntime) runControlFlowForEnrollment(ctx context.Context, enrollment localstore.Enrollment, tlsCfg tlsconfig.ClientConfig) {
	backoff := time.Second
	for ctx.Err() == nil {
		identity := runtimeIdentity{TenantID: enrollment.TenantID, AgentID: enrollment.AgentID, HostID: r.runner.currentIdentity().HostID}
		if err := r.runControlChannel(ctx, enrollment.GatewayAddress, "", tlsCfg, identity); err != nil && ctx.Err() == nil && r.runner.Out != nil {
			fmt.Fprintf(r.runner.Out, "agent managed control channel disconnected: %v\n", err)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
