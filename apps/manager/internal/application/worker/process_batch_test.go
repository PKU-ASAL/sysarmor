package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	domaindetection "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/detection"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestProcessBatchDecodesAndCommits(t *testing.T) {
	fixture := newProcessFixture()
	message := ports.RawMessage{Topic: "raw", Value: []byte("payload")}

	err := fixture.service.Process(context.Background(), message)

	if err != nil || fixture.decoder.calls != 1 || fixture.projector.calls != 1 || fixture.batches.committed != 1 {
		t.Fatalf("err=%v decode=%d project=%d commit=%d", err, fixture.decoder.calls, fixture.projector.calls, fixture.batches.committed)
	}
}

func TestProcessBatchStopsAfterDecodeFailure(t *testing.T) {
	fixture := newProcessFixture()
	want := errors.New("invalid batch")
	fixture.decoder.err = want

	err := fixture.service.Process(context.Background(), ports.RawMessage{})

	if !errors.Is(err, want) || fixture.batches.claimed != 0 {
		t.Fatalf("err=%v claims=%d", err, fixture.batches.claimed)
	}
}

func TestProcessBatchDuplicateIsSuccessful(t *testing.T) {
	fixture := newProcessFixture()
	fixture.batches.claim = ports.TelemetryDuplicate

	result, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err != nil || !result.Duplicate || fixture.projector.calls != 0 || fixture.batches.committed != 0 || fixture.batches.abandoned != 0 {
		t.Fatalf("result=%+v err=%v project=%d commit=%d abandon=%d", result, err, fixture.projector.calls, fixture.batches.committed, fixture.batches.abandoned)
	}
}

func TestProcessBatchBusyDoesNotAbandonForeignClaim(t *testing.T) {
	fixture := newProcessFixture()
	fixture.batches.claim = ports.TelemetryBusy

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.batches.abandoned != 0 || fixture.batches.committed != 0 {
		t.Fatalf("err=%v commit=%d abandon=%d", err, fixture.batches.committed, fixture.batches.abandoned)
	}
}

func TestProjectionFailureAbandonsClaim(t *testing.T) {
	fixture := newProcessFixture()
	fixture.projector.err = errors.New("opensearch unavailable")

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.batches.abandoned != 1 || fixture.batches.committed != 0 {
		t.Fatalf("err=%v abandon=%d commit=%d", err, fixture.batches.abandoned, fixture.batches.committed)
	}
}

func TestProcessBatchReportsAbandonFailure(t *testing.T) {
	fixture := newProcessFixture()
	projectionErr := errors.New("opensearch unavailable")
	abandonErr := errors.New("postgres abandon unavailable")
	fixture.projector.err = projectionErr
	fixture.batches.abandonErr = abandonErr

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if !errors.Is(err, projectionErr) || !errors.Is(err, abandonErr) {
		t.Fatalf("err=%v", err)
	}
}

func TestProcessBatchRenewsClaimWhileProcessing(t *testing.T) {
	fixture := newProcessFixture()
	blocked := make(chan struct{})
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{"scenario": "slow-analysis", "policy_id": "policy-a", "policy_version": "1"}
	fixture.decoder.batch.Events[0].Policy = ports.DetectionPolicyRef{ID: "policy-a", Version: 1}
	fixture.history.block = blocked
	fixture.batches.renewed = make(chan struct{}, 1)
	fixture.service.claimLease = 15 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)
		done <- err
	}()

	select {
	case <-fixture.batches.renewed:
		close(blocked)
	case <-time.After(time.Second):
		t.Fatal("telemetry claim was not renewed while history read was blocked")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProcessBatchStopsWhenClaimRenewalFails(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{"scenario": "slow-analysis", "policy_id": "policy-a", "policy_version": "1"}
	fixture.decoder.batch.Events[0].Policy = ports.DetectionPolicyRef{ID: "policy-a", Version: 1}
	fixture.history.block = make(chan struct{})
	fixture.batches.renewErr = errors.New("lease ownership lost")
	fixture.service.claimLease = 15 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, fixture.batches.renewErr) || fixture.batches.abandoned != 1 {
			t.Fatalf("err=%v abandoned=%d", err, fixture.batches.abandoned)
		}
	case <-time.After(time.Second):
		t.Fatal("processing continued after claim renewal failed")
	}
}

func TestCommitFailureAbandonsClaim(t *testing.T) {
	fixture := newProcessFixture()
	fixture.batches.commitErr = errors.New("postgres unavailable")

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.batches.abandoned != 1 || fixture.batches.committed != 1 {
		t.Fatalf("err=%v abandon=%d commit_attempts=%d", err, fixture.batches.abandoned, fixture.batches.committed)
	}
}

func TestHistoryFailureAbandonsClaim(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{"scenario": "checkout", "policy_id": "policy-a", "policy_version": "1"}
	fixture.decoder.batch.Events[0].Policy = ports.DetectionPolicyRef{ID: "policy-a", Version: 1}
	fixture.history.err = errors.New("history unavailable")

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.history.calls != 1 || fixture.batches.abandoned != 1 {
		t.Fatalf("err=%v history=%d abandon=%d", err, fixture.history.calls, fixture.batches.abandoned)
	}
}

func TestPolicyFailureAbandonsClaim(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{"scenario": "checkout", "policy_id": "policy-old", "policy_version": "3"}
	fixture.decoder.batch.Events[0].Policy = ports.DetectionPolicyRef{ID: "policy-old", Version: 3}
	fixture.policies.err = errors.New("policy unavailable")

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.policies.calls != 1 || fixture.batches.abandoned != 1 {
		t.Fatalf("err=%v policies=%d abandon=%d", err, fixture.policies.calls, fixture.batches.abandoned)
	}
}

func TestProcessBatchReadsTelemetryPolicyVersion(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{
		"scenario": "rollout-backlog", "policy_id": "policy-old", "policy_version": "3",
	}
	fixture.decoder.batch.Events[0].Policy = ports.DetectionPolicyRef{ID: "policy-old", Version: 3}

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err != nil || fixture.policies.policyID != "policy-old" || fixture.policies.version != 3 {
		t.Fatalf("err=%v policy=%s@%d", err, fixture.policies.policyID, fixture.policies.version)
	}
}

func TestProcessBatchRejectsAnalysisScopeWithoutPolicyIdentity(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Events[0].Event.Labels = map[string]string{"scenario": "missing-policy"}

	_, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	if err == nil || fixture.policies.calls != 0 || fixture.batches.abandoned != 1 {
		t.Fatalf("err=%v policies=%d abandon=%d", err, fixture.policies.calls, fixture.batches.abandoned)
	}
}

func TestProcessBatchProjectsDomainModelsAndMetrics(t *testing.T) {
	fixture := newProcessFixture()
	fixture.decoder.batch.Signals = []ports.ObservedSignal{{Signal: domaintelemetry.Signal{ID: "signal-a", Where: domaintelemetry.SignalWhereEndpoint}}}

	result, err := fixture.service.Execute(context.Background(), fixture.decoder.batch)

	projection := fixture.projector.projection
	delta := fixture.batches.delta
	if err != nil || result.AcceptedEvents != 1 || result.AcceptedSignals != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if projection.TenantID != tenant.ID("tenant-a") || len(projection.Events) != 1 || len(projection.Signals) != 1 {
		t.Fatalf("projection=%+v", projection)
	}
	if delta.TenantID != "tenant-a" || delta.BatchID != "batch-a" || delta.Metrics.Events != 1 || delta.Metrics.EndpointSignals != 1 {
		t.Fatalf("delta=%+v", delta)
	}
}

func TestObserveCloudSignalsUsesLatestContributingSignalTime(t *testing.T) {
	fallback := time.Unix(30, 0).UTC()
	inputs := []ports.ObservedSignal{
		{Signal: domaintelemetry.Signal{ID: "drop-a"}, ObservedAt: time.Unix(10, 0).UTC()},
		{Signal: domaintelemetry.Signal{ID: "exec-a"}, ObservedAt: time.Unix(20, 0).UTC()},
		{Signal: domaintelemetry.Signal{ID: "unrelated"}, ObservedAt: fallback},
	}
	cloud := []domaintelemetry.Signal{{ID: "cloud-a", SignalRefs: []string{"drop-a", "exec-a"}}}

	observed := observeCloudSignals(cloud, inputs, fallback)

	if len(observed) != 1 || !observed[0].ObservedAt.Equal(time.Unix(20, 0).UTC()) {
		t.Fatalf("observed = %+v", observed)
	}
}

func TestObserveCloudSignalsFallsBackWhenContributingSignalsAreMissing(t *testing.T) {
	fallback := time.Unix(30, 0).UTC()
	cloud := []domaintelemetry.Signal{{ID: "cloud-a", SignalRefs: []string{"missing"}}}

	observed := observeCloudSignals(cloud, nil, fallback)

	if len(observed) != 1 || !observed[0].ObservedAt.Equal(fallback) {
		t.Fatalf("observed = %+v", observed)
	}
}

func TestTouchedScopesSeparatePolicyVersions(t *testing.T) {
	labels := func(policyID, version string) map[string]string {
		return map[string]string{
			"scenario": "apt-staged-drop", "workload": "business-normal",
			"policy_id": policyID, "policy_version": version,
		}
	}
	batch := ports.DataBatch{Signals: []ports.ObservedSignal{
		{Signal: domaintelemetry.Signal{Labels: labels("balanced", "2")}, Policy: ports.DetectionPolicyRef{ID: "balanced", Version: 2}},
		{Signal: domaintelemetry.Signal{Labels: labels("deep", "2")}, Policy: ports.DetectionPolicyRef{ID: "deep", Version: 2}},
	}}

	scopes := touchedScopes(batch)

	if len(scopes) != 2 || scopes[0].labels["policy_id"] == "" || scopes[0].policy.ID == "" || scopes[1].labels["policy_id"] == "" {
		t.Fatalf("scopes = %+v", scopes)
	}
}

func TestProcessBatchRequiresDependencies(t *testing.T) {
	service := NewProcessBatch(nil, nil, nil, nil, nil, nil)
	if _, err := service.Execute(context.Background(), ports.DataBatch{}); err == nil {
		t.Fatal("incomplete ProcessBatch dependencies accepted")
	}
}

type processFixture struct {
	service   *ProcessBatch
	decoder   *batchDecoderStub
	projector *batchProjectorStub
	history   *historyReaderStub
	rarity    *rarityReaderStub
	batches   *telemetryBatchesStub
	policies  *detectionPoliciesStub
}

func newProcessFixture() *processFixture {
	batch := ports.DataBatch{
		TenantID: tenant.ID("tenant-a"), AgentID: identity.AgentID("agent-a"), ID: "batch-a", CreatedAt: time.Unix(1, 0).UTC(),
		Events: []ports.ObservedEvent{{Event: domaintelemetry.Event{ID: "event-a", TenantID: "tenant-a"}}},
	}
	fixture := &processFixture{
		decoder: &batchDecoderStub{batch: batch}, projector: &batchProjectorStub{}, history: &historyReaderStub{},
		rarity: &rarityReaderStub{}, batches: &telemetryBatchesStub{claim: ports.TelemetryClaimed, token: "claim-a"}, policies: &detectionPoliciesStub{},
	}
	fixture.service = NewProcessBatch(fixture.decoder, fixture.projector, fixture.history, fixture.rarity, fixture.batches, fixture.policies)
	return fixture
}

type batchDecoderStub struct {
	batch ports.DataBatch
	err   error
	calls int
}

func (stub *batchDecoderStub) Decode(ports.RawMessage) (ports.DataBatch, error) {
	stub.calls++
	return stub.batch, stub.err
}

type batchProjectorStub struct {
	projection ports.BatchProjection
	err        error
	calls      int
}

func (stub *batchProjectorStub) Project(_ context.Context, projection ports.BatchProjection) error {
	stub.calls++
	stub.projection = projection
	return stub.err
}

type historyReaderStub struct {
	err   error
	calls int
	block <-chan struct{}
}

func (stub *historyReaderStub) Read(ctx context.Context, _ tenant.ID, _ map[string]string, _, _ time.Time) (ports.HistorySnapshot, error) {
	stub.calls++
	if stub.block != nil {
		select {
		case <-stub.block:
		case <-ctx.Done():
			return ports.HistorySnapshot{}, ctx.Err()
		}
	}
	return ports.HistorySnapshot{}, stub.err
}

type rarityReaderStub struct{ err error }

func (stub *rarityReaderStub) Rarity(context.Context, tenant.ID) (identity.RarityBaseline, error) {
	return identity.RarityBaseline{}, stub.err
}

type telemetryBatchesStub struct {
	claim                                     ports.TelemetryClaim
	token                                     string
	claimErr, renewErr, commitErr, abandonErr error
	claimed, committed                        int
	abandoned                                 int
	renewed                                   chan struct{}
	delta                                     ports.TelemetryBatchDelta
}

func (stub *telemetryBatchesStub) Claim(context.Context, string, string, time.Duration) (ports.TelemetryClaim, string, error) {
	stub.claimed++
	return stub.claim, stub.token, stub.claimErr
}

func (stub *telemetryBatchesStub) Commit(_ context.Context, delta ports.TelemetryBatchDelta) error {
	stub.committed++
	stub.delta = delta
	return stub.commitErr
}

func (stub *telemetryBatchesStub) Renew(context.Context, string, string, string, time.Duration) error {
	if stub.renewed != nil {
		select {
		case stub.renewed <- struct{}{}:
		default:
		}
	}
	return stub.renewErr
}

func (stub *telemetryBatchesStub) Abandon(context.Context, string, string, string) error {
	stub.abandoned++
	return stub.abandonErr
}

type detectionPoliciesStub struct {
	err      error
	calls    int
	policyID domainpolicy.ID
	version  domainpolicy.Version
}

func (stub *detectionPoliciesStub) Published(_ context.Context, _ tenant.ID, policyID domainpolicy.ID, version domainpolicy.Version) (domaindetection.Policy, error) {
	stub.calls++
	stub.policyID, stub.version = policyID, version
	return domaindetection.Policy{}, stub.err
}
