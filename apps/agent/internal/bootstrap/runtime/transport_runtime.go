package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	grpcinbound "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/inbound/grpc"
	grpcoutbound "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/outbound/grpc"
	adapterresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/response"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	appresponse "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/response"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
)

func (r *TransportRuntime) runControlFlow(ctx context.Context) {
	dependencies := r.dependencies
	backoff := dependencies.config.Local.Export.RetryInitial
	if backoff <= 0 {
		backoff = time.Second
	}
	maxBackoff := dependencies.config.Local.Export.RetryMax
	if maxBackoff <= 0 {
		maxBackoff = 30 * time.Second
	}
	for {
		if err := r.RunControlChannel(ctx); err != nil && ctx.Err() == nil && dependencies.out != nil {
			fmt.Fprintf(dependencies.out, "agent control channel disconnected: %v\n", err)
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
	dependencies := r.dependencies
	identity := dependencies.management.currentIdentity()
	return r.runControlChannel(ctx, dependencies.config.Manager.Address, dependencies.config.Agent.Token, dependencies.management.managerTLS(), identity)
}

func (r *TransportRuntime) runControlChannel(ctx context.Context, manager, token string, tlsCfg tlsconfig.ClientConfig, identity runtimeIdentity) error {
	dependencies := r.dependencies
	connectCtx, cancel := context.WithTimeout(ctx, dependencies.config.Local.Export.RequestTimeout)
	defer cancel()
	session := grpcoutbound.NewControlChannel(manager, token, tlsCfg)
	if err := session.OpenSession(connectCtx, ctx); err != nil {
		return err
	}
	defer session.Close()
	frames, err := session.Hello(connectCtx, identity.TenantID, identity.AgentID, r.scopeType, r.scopeSelector)
	if err != nil {
		return err
	}
	dispatcher := r.newControlDispatcher()
	remoteIdentity := grpcinbound.Identity{TenantID: identity.TenantID, AgentID: identity.AgentID}
	if err := handleInitialControlFrames(ctx, session, dispatcher, remoteIdentity, frames); err != nil {
		return err
	}
	healthRuntime := newRuntimeHealth(dependencies.config, dependencies.out, dependencies.policy, dependencies.management, dependencies.sensorState)
	if err := r.sendRuntimeHealth(ctx, session, healthRuntime, identity); err != nil {
		return err
	}
	return r.serveControlChannel(ctx, session, dispatcher, remoteIdentity, healthRuntime, identity)
}

func (r *TransportRuntime) newControlDispatcher() *grpcinbound.Dispatcher {
	dependencies := r.dependencies
	return grpcinbound.NewDispatcher(grpcinbound.Dependencies{
		Policy:  dependencies.policy.policyController(r.sensor, r.batcher),
		Content: agentcontrol.NewContentController(newContentApplicationAdapter(dependencies.policy)),
		Response: appresponse.NewService(
			newResponseContext(dependencies.policy, r.scopeType, r.scopeSelector),
			adapterresponse.NewEnforcer(dependencies.sensorPort),
		),
	}, dependencies.out)
}

func handleInitialControlFrames(ctx context.Context, session *grpcoutbound.ControlChannel, dispatcher *grpcinbound.Dispatcher, identity grpcinbound.Identity, frames []*controlplanev1.ControlFrame) error {
	for _, frame := range frames {
		if frame.GetType() == "policy_update" {
			if err := dispatcher.HandleSnapshot(ctx, identity, frame); err != nil {
				return err
			}
			continue
		}
		if err := dispatcher.Handle(ctx, session, identity, frame); err != nil {
			return err
		}
	}
	return nil
}

func (r *TransportRuntime) sendRuntimeHealth(ctx context.Context, session *grpcoutbound.ControlChannel, healthRuntime runtimeHealth, identity runtimeIdentity) error {
	health := healthRuntime.collect(ctx, r.sensor, r.bus, r.batcher, r.sender, r.startedAt)
	health = bindHealthToSession(health, identity)
	if err := session.SendHealth(ctx, healthResponse(health)); err != nil {
		return err
	}
	return session.SendCapability(ctx, remoteCapabilityResponse(health))
}

func receiveControlFrames(ctx context.Context, session *grpcoutbound.ControlChannel) (<-chan *controlplanev1.ControlFrame, <-chan error) {
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
	return recvCh, errCh
}

func (r *TransportRuntime) serveControlChannel(ctx context.Context, session *grpcoutbound.ControlChannel, dispatcher *grpcinbound.Dispatcher, remoteIdentity grpcinbound.Identity, healthRuntime runtimeHealth, identity runtimeIdentity) error {
	recvCh, errCh := receiveControlFrames(ctx, session)
	interval := r.dependencies.config.Health.Interval
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
			if err := r.sendRuntimeHealth(ctx, session, healthRuntime, identity); err != nil {
				return err
			}
		}
	}
}

func (r *TransportRuntime) runControlFlowForEnrollment(ctx context.Context, enrollment sqlite.Enrollment, tlsCfg tlsconfig.ClientConfig) {
	backoff := time.Second
	for ctx.Err() == nil {
		identity := runtimeIdentity{EnrollmentEpoch: enrollment.EnrollmentID, TenantID: enrollment.TenantID, AgentID: enrollment.AgentID, HostID: r.dependencies.management.currentIdentity().HostID}
		if err := r.runControlChannel(ctx, enrollment.GatewayAddress, "", tlsCfg, identity); err != nil && ctx.Err() == nil && r.dependencies.out != nil {
			fmt.Fprintf(r.dependencies.out, "agent managed control channel disconnected: %v\n", err)
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
