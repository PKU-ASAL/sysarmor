package telemetry

import (
	"testing"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
	dataplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/dataplane/v1"
	eventv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/event/v1"
	signalv1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/signal/v1"
)

func TestBatchBuilderUsesCurrentContextForEveryBatch(t *testing.T) {
	provider := &contextProviderFake{context: ports.TelemetryContext{
		EnrollmentEpoch: "enroll-a",
		TenantID:        "local", AgentID: "device-a", HostID: "host-a",
		PolicyID: "standalone", PolicyVersion: 1, PolicyMode: "enforcing",
		Labels: map[string]string{"site": "lab"},
	}}
	builder := NewBatchBuilder(provider, 0)

	first := builder.NewBatch(time.Unix(1, 0).UTC())
	provider.context.TenantID = "tenant-a"
	provider.context.AgentID = "agent-a"
	provider.context.PolicyID = "managed-policy"
	provider.context.PolicyVersion = 7
	second := builder.NewBatch(time.Unix(2, 0).UTC())

	assertHeader(t, first.GetHeader(), "local", "device-a", "standalone", 1)
	assertHeader(t, second.GetHeader(), "tenant-a", "agent-a", "managed-policy", 7)
	if second.GetHeader().GetEnrollmentEpoch() != "enroll-a" {
		t.Fatalf("enrollment epoch = %q", second.GetHeader().GetEnrollmentEpoch())
	}
	if got := second.GetHeader().GetLabels()["site"]; got != "lab" {
		t.Fatalf("site label = %q, want lab", got)
	}
	if got := second.GetHeader().GetLabels()["policy_version"]; got != "7" {
		t.Fatalf("policy_version label = %q, want 7", got)
	}
}

func TestBatchBuilderPreservesEventSequenceAndResumesSignalSequence(t *testing.T) {
	builder := NewBatchBuilder(&contextProviderFake{}, 17)
	event := &eventv1.CanonicalEvent{Id: "event-a", Seq: 41}
	signal := &signalv1.Signal{Id: "source-id", Labels: map[string]string{"source": "sensor"}, Evidence: &signalv1.EvidenceBundle{Id: "source-evidence"}}

	batch := builder.ForEvent(time.Unix(3, 0).UTC(), event, []*signalv1.Signal{signal})

	if got := batch.GetEvents()[0].GetSequence(); got != 41 {
		t.Fatalf("event sequence = %d, want 41", got)
	}
	frame := batch.GetSignals()[0]
	if frame.GetSequence() != 18 || frame.GetSignal().GetId() != "sig-00000000000000000018" {
		t.Fatalf("signal frame = %+v", frame)
	}
	if got := frame.GetSignal().GetEvidence().GetId(); got != "evb-sig-00000000000000000018" {
		t.Fatalf("evidence id = %q", got)
	}
	if signal.GetId() != "source-id" || signal.GetEvidence().GetId() != "source-evidence" {
		t.Fatalf("input signal was modified: %+v", signal)
	}
}

func TestBatchBuilderAddsPolicyLabelsWithoutMutatingSignals(t *testing.T) {
	provider := &contextProviderFake{context: ports.TelemetryContext{
		PolicyID: "policy-a", PolicyVersion: 9, PolicyMode: "observe",
	}}
	builder := NewBatchBuilder(provider, 20)
	signal := &signalv1.Signal{Id: "external", Labels: map[string]string{"origin": "control"}}

	batch := builder.ForSignals(time.Unix(4, 0).UTC(), []*signalv1.Signal{signal})

	frame := batch.GetSignals()[0]
	if frame.GetSequence() != 21 || frame.GetSignal().GetId() != "external" {
		t.Fatalf("signal frame = %+v", frame)
	}
	wantLabels := map[string]string{"origin": "control", "policy_id": "policy-a", "policy_version": "9", "policy_mode": "observe"}
	for key, want := range wantLabels {
		if got := frame.GetSignal().GetLabels()[key]; got != want {
			t.Fatalf("label %s = %q, want %q", key, got, want)
		}
	}
	if len(signal.GetLabels()) != 1 || signal.GetLabels()["origin"] != "control" {
		t.Fatalf("input labels were modified: %+v", signal.GetLabels())
	}
}

func TestBatchBuilderUsesOneContextSnapshotForSignalBatch(t *testing.T) {
	provider := &switchingContextProvider{contexts: []ports.TelemetryContext{
		{PolicyID: "policy-old", PolicyVersion: 1},
		{PolicyID: "policy-new", PolicyVersion: 2},
	}}
	builder := NewBatchBuilder(provider, 0)

	batch := builder.ForSignals(time.Unix(5, 0).UTC(), []*signalv1.Signal{{Id: "external"}})

	if provider.calls != 1 {
		t.Fatalf("context reads = %d, want 1", provider.calls)
	}
	if batch.GetHeader().GetPolicyId() != "policy-old" || batch.GetSignals()[0].GetSignal().GetLabels()["policy_id"] != "policy-old" {
		t.Fatalf("inconsistent policy snapshot: header=%+v signal=%+v", batch.GetHeader(), batch.GetSignals()[0].GetSignal())
	}
}

type contextProviderFake struct{ context ports.TelemetryContext }

func (p *contextProviderFake) TelemetryContext() ports.TelemetryContext { return p.context }

type switchingContextProvider struct {
	contexts []ports.TelemetryContext
	calls    int
}

func (p *switchingContextProvider) TelemetryContext() ports.TelemetryContext {
	context := p.contexts[min(p.calls, len(p.contexts)-1)]
	p.calls++
	return context
}

func assertHeader(t *testing.T, header *dataplanev1.BatchHeader, tenantID, agentID, policyID string, version uint64) {
	t.Helper()
	if header.GetTenantId() != tenantID || header.GetAgentId() != agentID || header.GetPolicyId() != policyID || header.GetPolicyVersion() != version {
		t.Fatalf("header = %+v", header)
	}
}
