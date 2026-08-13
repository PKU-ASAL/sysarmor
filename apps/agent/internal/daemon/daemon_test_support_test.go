package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/config"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/fake"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/linux/tetragon"
	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/sensors/runtime"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/telemetry/dataappend"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	sensorv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/sensor/v1"
	policymodel "github.com/sysarmor/sysarmor-next-project/packages/policy"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
	"google.golang.org/grpc"
)

func newConfiguredTestRuntime(t testing.TB, cfg config.Config) *AgentRuntime {
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
	dependencies := Dependencies{Config: cfg, Sensor: sensor, Content: agentcontent.NewStore()}
	if cfg.Manager.Transport == "" {
		store, err := localstore.Open(context.Background(), localstore.Options{
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
	return NewRuntime(dependencies)
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

func runTestControlChannel(t *testing.T, dir string, server *contentUpdateControlServer, agentID string) (*AgentRuntime, <-chan error, context.CancelFunc) {
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

	runner := &AgentRuntime{
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
	installTestDetection(t, runner)
	if server.initialContentJSON != "" {
		if _, err := runner.contentStore().Apply(server.initialContentJSON, true, false); err != nil {
			t.Fatalf("install valid runtime content: %v", err)
		}
	}
	ensureTestLocalStore(t, runner)
	if err := runner.localStore.SetEnrolling(context.Background(), localstore.Enrollment{
		TenantID: "default", AgentID: agentID, EnrollmentID: "test-enrollment-" + agentID,
		CertificateSerial: "test-serial", ManagerURL: "https://manager.test", GatewayAddress: "gateway",
		TLSCAPath: "/test/ca", TLSCertPath: "/test/cert", TLSKeyPath: "/test/key",
	}); err != nil {
		t.Fatalf("initialize managed enrollment: %v", err)
	}
	runner.applyRuntimePolicy(policymodel.DefaultPolicy("default"))
	rt := sensorruntime.New(runner.Sensor)
	batcher := telemetry.NewBatcher(runner.newDataBatch, 10, time.Hour, 16)
	sender := &telemetry.Sender{Appender: noopUploader{}, Batcher: batcher}
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

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

type eventSensor struct {
	events []contract.EventEnvelope
	ch     chan contract.EventEnvelope
	health contract.Health
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type capabilityErrorSensor struct {
	err error
}

func newStreamingEventSensor() *eventSensor {
	s := newEventSensor(nil)
	s.ch = make(chan contract.EventEnvelope, 16)
	return s
}

func (s *eventSensor) emit(ev contract.EventEnvelope) {
	s.ch <- ev
}

func newEventSensor(events []contract.EventEnvelope) *eventSensor {
	return &eventSensor{
		events: events,
		health: contract.Health{
			Backend:      "test",
			Installed:    true,
			Running:      true,
			Version:      "test",
			PolicyLoaded: true,
		},
	}
}

func (s *capabilityErrorSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{}, s.err
}

func (s *capabilityErrorSensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *capabilityErrorSensor) Subscribe(context.Context, contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	return nil, nil
}

func (s *capabilityErrorSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *capabilityErrorSensor) Health(context.Context) (contract.Health, error) {
	return contract.Health{}, nil
}

func (s *healthOnlySensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: s.health.Backend, Version: "test", SupportsHealth: true}, nil
}

func (s *healthOnlySensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *healthOnlySensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	go func() {
		defer close(out)
		<-ctx.Done()
	}()
	return out, nil
}

func (s *healthOnlySensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *healthOnlySensor) Health(context.Context) (contract.Health, error) {
	return s.health, nil
}

func (s *eventSensor) Capability(context.Context) (contract.Capability, error) {
	return contract.Capability{Backend: "test", Version: "test", SupportsExec: true, SupportsFile: true, SupportsHealth: true}, nil
}

func (s *eventSensor) Apply(context.Context, contract.CollectionIntent) (contract.ApplyResult, error) {
	s.health.PolicyLoaded = true
	return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
}

func (s *eventSensor) Subscribe(ctx context.Context, _ contract.CollectionIntent) (<-chan contract.EventEnvelope, error) {
	out := make(chan contract.EventEnvelope)
	events := append([]contract.EventEnvelope(nil), s.events...)
	go func() {
		defer close(out)
		for _, ev := range events {
			select {
			case <-ctx.Done():
				return
			case out <- ev:
				s.health.EventsSeen++
				s.health.LastEventAt = time.Now().UTC()
			}
		}
		if s.ch == nil {
			<-ctx.Done()
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-s.ch:
				select {
				case <-ctx.Done():
					return
				case out <- ev:
					s.health.EventsSeen++
					s.health.LastEventAt = time.Now().UTC()
				}
			}
		}
	}()
	return out, nil
}

func (s *eventSensor) Enforce(_ context.Context, cmd contract.EnforcementCmd) (contract.EnforcementAck, error) {
	return contract.UnsupportedAck(cmd, "test sensor"), nil
}

func (s *eventSensor) Health(context.Context) (contract.Health, error) {
	return s.health, nil
}

func sensorEventEnvelope(behavior string, pid uint32, binary, filePath, dst string) contract.EventEnvelope {
	return contract.EventEnvelope{
		SensorEvent: &sensorv1.SensorEvent{
			Behavior: behavior,
			Proc: &sensorv1.RawProcess{
				Pid:         pid,
				Binary:      binary,
				StartTimeNs: uint64(time.Now().UnixNano()),
			},
			Object: &sensorv1.RawObject{
				Path: filePath,
				Dst:  dst,
			},
			RawRef: "test-policy-event",
		},
		RawRef: "test-policy-event",
	}
}

func runDaemonUntilUploadedBatch(t *testing.T, runner *AgentRuntime, out *bytes.Buffer) *dataplanev1.DataBatch {
	t.Helper()
	uploader := newRecordingUploader()
	prev := newLocalBatchSender
	newLocalBatchSender = func() dataappend.BatchSender { return uploader }
	t.Cleanup(func() { newLocalBatchSender = prev })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		opts := Options{}
		if out != nil {
			opts.Out = out
		}
		errCh <- runner.Run(ctx, opts)
	}()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case batch := <-uploader.ch:
			cancel()
			if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			return batch
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			t.Fatalf("daemon exited before uploading a telemetry batch")
		case <-deadline:
			cancel()
			t.Fatalf("timed out waiting for uploaded telemetry batch")
		}
	}
}

func runDaemonUntilOutput(t *testing.T, runner *AgentRuntime, out interface {
	Write([]byte) (int, error)
	String() string
}, want string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx, Options{Out: out})
	}()
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(out.String(), want) {
			cancel()
			if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			return
		}
		select {
		case err := <-errCh:
			if strings.Contains(out.String(), want) {
				return
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error = %v", err)
			}
			t.Fatalf("daemon exited before output %q; got %q", want, out.String())
		case <-deadline:
			cancel()
			t.Fatalf("timed out waiting for output %q; got %q", want, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForOutput(t *testing.T, out interface{ String() string }, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(out.String(), want) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for output %q; got %q", want, out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func testDataBatch(batchID, agentID, hostID string) *dataplanev1.DataBatch {
	return &dataplanev1.DataBatch{
		Header: &dataplanev1.BatchHeader{BatchId: batchID, AgentId: agentID, HostId: hostID, TenantId: "default"},
	}
}

func containsInt(items []int, want int) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
