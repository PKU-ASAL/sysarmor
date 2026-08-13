package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	eventadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/remoteapi"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"github.com/sysarmor/sysarmor-next-project/packages/tlsconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestControlChannelKeepsLongLivedContract(t *testing.T) {
	server := &healthControlContractServer{received: make(chan *controlplanev1.HealthResponse, 1)}
	address := startControlContractServer(t, server)

	session := remoteapi.NewControlChannel(address, "", tlsconfig.ClientConfig{})
	defer session.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frames, err := session.Hello(ctx, "default", "agent-long-control", "container", "api")
	if err != nil {
		t.Fatalf("Hello() error = %v", err)
	}
	if len(frames) != 2 || frames[0].GetType() != "policy_update" || frames[1].GetType() != "resume" {
		t.Fatalf("hello frames = %+v", frames)
	}
	if frames[0].GetContractVersion() != 1 || frames[0].GetSequence() != 1 || frames[1].GetSequence() != 2 {
		t.Fatalf("hello frame sequence = %d/%d contract=%d", frames[0].GetSequence(), frames[1].GetSequence(), frames[0].GetContractVersion())
	}
	if err := session.Send(ctx, &controlplanev1.ControlFrame{
		Type:      "health_report",
		RequestId: "long-health",
		Context: &controlplanev1.RequestContext{
			TenantId: "default",
			AgentId:  "agent-long-control",
			Scope:    &controlplanev1.Scope{Type: "container", Selector: "api"},
		},
		Health: &controlplanev1.HealthResponse{
			AgentId:    "agent-long-control",
			HostId:     "host-long-control",
			TenantId:   "default",
			Status:     "ok",
			Scope:      &controlplanev1.Scope{Type: "container", Selector: "api"},
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Capability: &controlplanev1.SensorCapability{Backend: "fake", Version: "long", SupportsHealth: true},
			Sensor:     &controlplanev1.SensorHealth{Backend: "fake", Running: true, EventsSeen: 7},
		},
	}); err != nil {
		t.Fatalf("Send(health) error = %v", err)
	}
	ack, err := session.Recv()
	if err != nil {
		t.Fatalf("Recv(health ack) error = %v", err)
	}
	if ack.GetType() != "ack" || ack.GetSequence() != 3 || ack.GetAck().GetStatus() != "accepted" {
		t.Fatalf("health ack = %+v", ack)
	}
	got := <-server.received
	if got.GetCapability().GetVersion() != "long" || got.GetSensor().GetEventsSeen() != 7 {
		t.Fatalf("received long stream health = %+v", got)
	}
}

func TestControlChannelHelloStopsWhenSessionContextIsCanceled(t *testing.T) {
	received := make(chan struct{})
	grpcServer := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(grpcServer, &blockingHelloControlServer{received: received})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	session := remoteapi.NewControlChannel(lis.Addr().String(), "", tlsconfig.ClientConfig{})
	defer session.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := session.Hello(ctx, "default", "agent-a", "host", "")
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("server did not receive hello")
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("Hello() error=%v, want context canceled", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Hello() did not stop after session cancellation")
	}
}

type blockingHelloControlServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	received chan struct{}
}

func (s *blockingHelloControlServer) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	close(s.received)
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestAgentRuntimeControlChannelProcessesPendingResponse(t *testing.T) {
	server := &responseControlContractServer{observed: make(chan responseControlObservation, 1)}
	address := startControlContractServer(t, server)

	runner := &AgentRuntime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: "agent-runner-long", HostID: "host-runner-long", TenantID: "default"},
			Manager: config.ManagerConfig{Address: address, Transport: "grpc"},
			Local:   config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond, RequestTimeout: time.Second, MaxInflight: 1}},
			Health:  config.HealthConfig{Interval: 10 * time.Millisecond},
		},
		Sensor: &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, PolicyLoaded: true, EventsSeen: 3}},
		capability: contract.Capability{
			Backend:        "fake",
			Version:        "long",
			SupportsHealth: true,
		},
	}
	runner.policyController = newApplicationPolicyController
	rt := sensorruntime.New(runner.Sensor)
	batcher := telemetry.NewBatcher(runner.newTelemetryBatchBuilder().NewBatch, 10, time.Hour, 16)
	sender := &telemetry.Sender{Appender: noopUploader{}, Batcher: batcher}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewTransportRuntime(runner, rt, batcher, sender, time.Now().UTC(), "host", "").RunControlChannel(ctx)
	}()
	var observation responseControlObservation
	select {
	case observation = <-server.observed:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("response ack not observed")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunControlChannel() error = %v", err)
	}
	ack := observation.ack
	if ack.GetResponseId() != "resp-runner-long" || !ack.GetAccepted() || !ack.GetObserveOnly() || ack.GetExecuted() {
		t.Fatalf("ack = %+v", ack)
	}
	if observation.capability.GetSensor().GetVersion() != "long" {
		t.Fatalf("capability = %+v", observation.capability)
	}
}

func TestAgentRuntimeControlChannelAppliesContentUpdate(t *testing.T) {
	dir := t.TempDir()
	server := &contentUpdateControlServer{
		tenantID: "default",
		agentID:  "agent-content-update",
		contentJSON: `{
			"api_version":"sysarmor.content/v1",
			"kind":"iocpack",
			"metadata":{"id":"ioc:c2-control-port-feed","version":"control-9443"},
			"spec":{"value_type":"port","values":["9443"]}
		}`,
	}
	runner, done, cancel := runTestControlChannel(t, dir, server, "agent-content-update")
	defer cancel()

	ack := waitForControlAck(t, server, "content-update-1")
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunControlChannel() error = %v", err)
	}
	if ack.GetStatus() != "applied" || ack.GetPolicyId() != "ioc:c2-control-port-feed" {
		t.Fatalf("content ack = %+v", ack)
	}
	if record, ok := runner.contentStore().Get("ioc:c2-control-port-feed"); !ok || record.Version != "control-9443" {
		t.Fatalf("content record = %+v ok=%t", record, ok)
	}

	batch := appendEndpointEventForTest(t, runner, nil, eventadapter.NewEventNormalizer("agent-content-update", "host-content-update", eventadapter.EventNormalizerOptions{}), sensorEventEnvelope("network.connect", 100, "/bin/bash", "", "10.66.0.99:9443"))
	if len(batch.GetSignals()) == 0 {
		t.Fatalf("signals after content update = none, want detection runtime to use updated content")
	}
}

func TestAgentRuntimeAppliesHandshakePolicyWithoutCommandAck(t *testing.T) {
	server := &contentUpdateControlServer{
		tenantID: "default",
		agentID:  "agent-handshake-policy",
		contentJSON: `{
			"api_version":"sysarmor.content/v1",
			"kind":"iocpack",
			"metadata":{"id":"ioc:handshake-test","version":"v1"},
			"spec":{"value_type":"port","values":["9443"]}
		}`,
	}
	_, done, cancel := runTestControlChannel(t, t.TempDir(), server, "agent-handshake-policy")
	defer cancel()

	waitForControlAck(t, server, "content-update-1")
	select {
	case ack := <-server.snapshotAcks:
		t.Fatalf("handshake policy snapshot sent command ack: %+v", ack)
	default:
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunControlChannel() error = %v", err)
	}
}

func TestAgentRuntimeControlChannelRejectsBadContentUpdateWithoutReplacingDetection(t *testing.T) {
	dir := t.TempDir()
	server := &contentUpdateControlServer{
		tenantID:           "default",
		agentID:            "agent-bad-content-update",
		initialContentJSON: validBadRuntimeRulePackJSON(),
		contentJSON: `{
			"api_version":"sysarmor.content/v1",
			"kind":"rulepack",
			"metadata":{"id":"rulepack:bad-runtime","version":"bad-v1"},
			"spec":{"rulesets":[{"id":"ruleset:cep-endpoint","version":"v1","rules":[{
				"rule_id":"bad_runtime_rule",
				"version":1,
				"severity":"high",
				"runtime":{"type":"made_up_runtime"}
			}]}]}
		}`,
		policy: badRuntimeCandidatePolicy("default"),
	}
	runner, done, cancel := runTestControlChannel(t, dir, server, "agent-bad-content-update")
	defer cancel()

	ack := waitForControlAck(t, server, "content-update-1")
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RunControlChannel() error = %v", err)
	}
	if ack.GetStatus() != "rejected" || !strings.Contains(ack.GetMessage(), "detection rebuild failed") {
		t.Fatalf("bad content ack = %+v", ack)
	}
	if record, ok := runner.contentStore().Get("rulepack:bad-runtime"); !ok || record.Version != "v1" {
		t.Fatalf("content after rejected update = %+v ok=%t, want previous v1", record, ok)
	}
	batch := appendEndpointEventForTest(t, runner, nil, eventadapter.NewEventNormalizer("agent-bad-content-update", "host-bad-content-update", eventadapter.EventNormalizerOptions{}), sensorEventEnvelope("file.write", 101, "/usr/bin/curl", "/dev/shm/kept-control.sh", ""))
	if len(batch.GetSignals()) != 1 || batch.GetSignals()[0].GetSignal().GetName() != "payload_dropped" {
		t.Fatalf("signals after rejected content update = %+v, want previous detection engine active", batch.GetSignals())
	}
}
