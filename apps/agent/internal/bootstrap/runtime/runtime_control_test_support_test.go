package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/config"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/fake"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/tetragon"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	telemetryadapter "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/telemetry"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/grpc"
)

func newConfiguredTestRuntime(t testing.TB, cfg config.Config) *Runtime {
	t.Helper()
	var sensor contract.Sensor
	switch cfg.Sensor.Backend {
	case "fake":
		sensor = fake.NewWithStartupEvents(max(cfg.Sensor.FakeStartupEvents, 1))
	case "tetragon":
		sensor = tetragon.NewBackend(cfg.Sensor.PolicyPath, cfg.Sensor.EventSource, cfg.Sensor.Version)
	default:
		t.Fatalf("unsupported test sensor backend %q", cfg.Sensor.Backend)
	}
	dependencies := Dependencies{Config: cfg, Sensor: sensor, Content: agentcontent.NewStore(), Policy: newApplicationPolicyController}
	if cfg.Manager.Transport == "" {
		store, err := sqlite.Open(context.Background(), sqlite.Options{
			RootDir: cfg.Local.StatePath, MaxBytes: cfg.Local.Storage.MaxBytes, MinFreeBytes: cfg.Local.Storage.MinFreeBytes,
			SegmentSize: cfg.Local.Storage.SegmentSize, SignalMaxCount: cfg.Local.Storage.SignalMaxCount,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		identity, err := store.DeviceIdentity(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if dependencies.Config.Agent.ID == "" {
			dependencies.Config.Agent.ID = identity.DeviceID
		}
		if dependencies.Config.Agent.HostID == "" {
			dependencies.Config.Agent.HostID = identity.HostID
		}
		if dependencies.Config.Agent.TenantID == "" {
			dependencies.Config.Agent.TenantID = "local"
		}
		cursor, err := store.SequenceCursor(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		dependencies.LocalStore, dependencies.EventSeq, dependencies.SignalSeq = store, cursor.Event, cursor.Signal
	}
	runtime, err := NewRuntime(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

type healthOnlySensor struct {
	health contract.Health
}

type contentUpdateControlServer struct {
	controlplanev1.UnimplementedAgentControlPlaneServiceServer
	tenantID           string
	agentID            string
	initialContentJSON string
	contentJSON        string
	policy             policymodel.Policy
	acks               chan *controlplanev1.ControlAck
	snapshotAcks       chan *controlplanev1.ControlAck
}

func (s *contentUpdateControlServer) Connect(stream controlplanev1.AgentControlPlaneService_ConnectServer) error {
	hello, err := stream.Recv()
	if err != nil {
		return err
	}
	if hello.GetType() != "hello" {
		return fmt.Errorf("first frame type = %q, want hello", hello.GetType())
	}
	tenantID := firstNonEmptyString(s.tenantID, "default")
	agentID := firstNonEmptyString(s.agentID, hello.GetContext().GetAgentId())
	policy := s.policy
	if policy.PolicyID == "" {
		policy = policymodel.ManagerDefaultPolicy(tenantID)
	}
	policy.TenantID = tenantID
	endpoint := policy.EndpointPolicy()
	endpointPolicy := agentpolicy.EndpointPolicy{PolicyID: endpoint.PolicyID, Version: endpoint.Version,
		Collection: endpoint.Collection, Detection: endpoint.Detection,
		Telemetry: policymodel.TelemetryPolicy{MaxBatchItems: 256, MaxBatchBytes: 256 << 10, FlushInterval: "1s"}, Response: policy.Response}
	rawPolicy, _ := json.Marshal(endpointPolicy)
	for _, frame := range []*controlplanev1.ControlFrame{{
		Type:            "policy_update",
		RequestId:       hello.GetRequestId(),
		ContractVersion: 1,
		Sequence:        1,
		Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: agentID},
		PolicyUpdate: &controlplanev1.CurrentPolicyResponse{
			PolicyId: policy.PolicyID,
			Version:  policy.Version,
			TenantId: tenantID,
			Mode:     policy.Mode,
			RawJson:  string(rawPolicy),
		},
	}, {
		Type:            "resume",
		RequestId:       hello.GetRequestId(),
		ContractVersion: 1,
		Sequence:        2,
		Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: agentID},
		Resume:          &controlplanev1.ResumeCursor{TenantId: tenantID, AgentId: agentID},
	}, {
		Type:            "content_update",
		RequestId:       "content-update-1",
		ContractVersion: 1,
		Sequence:        3,
		Context:         &controlplanev1.RequestContext{TenantId: tenantID, AgentId: agentID, RequestId: "content-update-1"},
		ContentUpdate: &controlplanev1.ApplyContentRequest{
			Context:       &controlplanev1.RequestContext{TenantId: tenantID, AgentId: agentID, RequestId: "content-update-1"},
			ContentJson:   s.contentJSON,
			AllowUnsigned: true,
		},
	}} {
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if frame.GetType() == "ack" && frame.GetAck().GetRequestId() == hello.GetRequestId() {
			s.snapshotAcks <- frame.GetAck()
			continue
		}
		if frame.GetType() == "ack" && frame.GetAck().GetRequestId() == "content-update-1" {
			s.acks <- frame.GetAck()
			return nil
		}
	}
}

func runTestControlChannel(t *testing.T, dir string, server *contentUpdateControlServer, agentID string) (*Runtime, <-chan error, context.CancelFunc) {
	t.Helper()
	if server.acks == nil {
		server.acks = make(chan *controlplanev1.ControlAck, 1)
	}
	if server.snapshotAcks == nil {
		server.snapshotAcks = make(chan *controlplanev1.ControlAck, 1)
	}
	grpcServer := grpc.NewServer()
	controlplanev1.RegisterAgentControlPlaneServiceServer(grpcServer, server)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.Stop)

	runner := &Runtime{
		Config: config.Config{
			Agent:   config.AgentConfig{ID: agentID, HostID: "host-" + agentID, TenantID: "default"},
			Manager: config.ManagerConfig{Address: lis.Addr().String(), Transport: "grpc"},
			Local:   config.LocalConfig{Export: config.LocalExportConfig{RetryInitial: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond, RequestTimeout: time.Second, MaxInflight: 1}},
			Health:  config.HealthConfig{Interval: time.Hour},
		},
		Sensor: &healthOnlySensor{health: contract.Health{Backend: "fake", Running: true, PolicyLoaded: true, EventsSeen: 3}},
		capability: contract.Capability{
			Backend:        "fake",
			Version:        "long",
			SupportsHealth: true,
		},
	}
	runner.policyController = newApplicationPolicyController
	installTestDetection(t, runner)
	if server.initialContentJSON != "" {
		if _, err := runner.contentStore().Apply(server.initialContentJSON, true, false); err != nil {
			t.Fatalf("install valid runtime content: %v", err)
		}
	}
	ensureTestLocalStore(t, runner)
	if err := runner.localStore.SetEnrolling(context.Background(), sqlite.Enrollment{
		TenantID: "default", AgentID: agentID, EnrollmentID: "test-enrollment-" + agentID,
		CertificateSerial: "test-serial", ManagerURL: "https://manager.test", GatewayAddress: "gateway",
		TLSCAPath: "/test/ca", TLSCertPath: "/test/cert", TLSKeyPath: "/test/key",
	}); err != nil {
		t.Fatalf("initialize managed enrollment: %v", err)
	}
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	rt := sensorruntime.New(runner.Sensor)
	batcher := telemetryadapter.NewBatcher(runner.newTelemetryBatchBuilder().NewBatch, 10, time.Hour, 16)
	sender := telemetryadapter.NewRuntimeSender(batcher, noopUploader{}, 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- NewTransportRuntime(runner, rt, batcher, sender, time.Now().UTC(), "host", "").RunControlChannel(ctx)
	}()
	return runner, done, cancel
}

func waitForControlAck(t *testing.T, server *contentUpdateControlServer, requestID string) *controlplanev1.ControlAck {
	t.Helper()
	select {
	case ack := <-server.acks:
		if ack.GetRequestId() != requestID {
			t.Fatalf("ack request_id = %q, want %q", ack.GetRequestId(), requestID)
		}
		return ack
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for control ack %q", requestID)
		return nil
	}
}

func badRuntimeCandidatePolicy(tenantID string) policymodel.Policy {
	policy := policymodel.ManagerDefaultPolicy(tenantID)
	policy.PolicyID = "bad-runtime-candidate"
	policy.Version = 2
	enabled := true
	policy.Detection.RuleSets = append(policy.Detection.RuleSets, policymodel.RuleSetRef{Ref: "ruleset:bad-runtime", Enabled: &enabled})
	return policy
}

func validBadRuntimeRulePackJSON() string {
	return `{"api_version":"sysarmor.content/v1","kind":"rulepack","metadata":{"id":"rulepack:bad-runtime","version":"v1"},"spec":{"rulesets":[{"id":"ruleset:bad-runtime","version":"v1","rules":[{"rule_id":"valid_runtime_rule","version":1,"severity":"low","runtime":{"type":"sequence","sequence":{"within":"10s","steps":[{"id":"exit","event":"process.exit"}]}}}]}]}}`
}
