package control

import (
	"context"
	"errors"
	"strings"
	"testing"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/detection"
)

type recordingContentRuntime struct {
	identity        ContentIdentity
	beginErr        error
	contextErr      error
	validateErr     error
	prepareErr      error
	commitErr       error
	record          agentcontent.Record
	snapshot        agentcontent.Snapshot
	build           ContentDetectionBuild
	beginMutations  []bool
	validated       int
	prepared        int
	transactions    int
	committed       int
	activated       int
	rejectedReports []detection.ApplyReport
	listKind        string
	getRef          string
}

func (r *recordingContentRuntime) ContentIdentity() ContentIdentity { return r.identity }

func (r *recordingContentRuntime) BeginLocalContentMutation(_ context.Context, mutation bool) (func(), error) {
	r.beginMutations = append(r.beginMutations, mutation)
	return func() {}, r.beginErr
}

func (r *recordingContentRuntime) ValidateContentContext(ctx RequestContext) error {
	if r.contextErr != nil {
		return r.contextErr
	}
	if ctx.TenantID != "" && ctx.TenantID != r.identity.TenantID {
		return errors.New("tenant mismatch")
	}
	if ctx.AgentID != "" && ctx.AgentID != r.identity.AgentID {
		return errors.New("agent mismatch")
	}
	return nil
}

func (r *recordingContentRuntime) ValidateContent(string, bool) (agentcontent.Record, error) {
	r.validated++
	return r.record, r.validateErr
}

func (r *recordingContentRuntime) WithContentTransaction(run func()) {
	r.transactions++
	run()
}

func (r *recordingContentRuntime) PrepareContent(string, bool) (agentcontent.Record, agentcontent.Snapshot, error) {
	r.prepared++
	return r.record, r.snapshot, r.prepareErr
}

func (r *recordingContentRuntime) BuildContentDetection(agentcontent.Snapshot) ContentDetectionBuild {
	return r.build
}

func (r *recordingContentRuntime) RecordRejectedContentDetection(report detection.ApplyReport) {
	r.rejectedReports = append(r.rejectedReports, report)
}

func (r *recordingContentRuntime) CommitContent(agentcontent.Record) error {
	r.committed++
	return r.commitErr
}

func (r *recordingContentRuntime) ActivateContentDetection(agentcontent.Snapshot, ContentDetectionBuild) {
	r.activated++
}

func (r *recordingContentRuntime) ListContent(kind string) []agentcontent.Record {
	r.listKind = kind
	return []agentcontent.Record{r.record}
}

func (r *recordingContentRuntime) GetContent(ref string) (agentcontent.Record, bool) {
	r.getRef = ref
	return r.record, true
}

func TestContentControllerDryRunValidatesWithoutStartingTransaction(t *testing.T) {
	runtime := newRecordingContentRuntime()
	result := NewContentController(runtime).ApplyContent(t.Context(), ContentCommand{
		Context:  RequestContext{RequestID: "request-a", TenantID: "tenant-a", AgentID: "agent-a"},
		Document: "{}", DryRun: true, AllowUnsigned: true, Source: PolicySourceStandalone,
	})

	if result.Status != "validated" || runtime.validated != 1 || runtime.prepared != 0 || runtime.transactions != 0 || runtime.committed != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
	if len(runtime.beginMutations) != 1 || runtime.beginMutations[0] {
		t.Fatalf("begin mutations=%v, want [false]", runtime.beginMutations)
	}
}

func TestContentControllerRejectedRebuildKeepsPreparedContentUncommitted(t *testing.T) {
	runtime := newRecordingContentRuntime()
	runtime.build.Report = detection.ApplyReport{Status: "rejected", Details: []string{"unsupported runtime"}}
	result := NewContentController(runtime).ApplyContent(t.Context(), ContentCommand{
		Context: RequestContext{RequestID: "request-a"}, Document: "{}", AllowUnsigned: true,
	})

	if result.Status != "rejected" || !strings.Contains(result.Message, "detection rebuild failed") {
		t.Fatalf("result=%+v", result)
	}
	if runtime.prepared != 1 || runtime.committed != 0 || len(runtime.rejectedReports) != 1 {
		t.Fatalf("runtime=%+v", runtime)
	}
}

func TestContentControllerCommitFailureDoesNotReturnApplied(t *testing.T) {
	runtime := newRecordingContentRuntime()
	runtime.commitErr = errors.New("persist content: disk full")
	result := NewContentController(runtime).ApplyContent(t.Context(), ContentCommand{
		Context: RequestContext{RequestID: "request-a"}, Document: "{}", AllowUnsigned: true,
	})

	if result.Status != "rejected" || !strings.Contains(result.Message, "disk full") || runtime.committed != 1 || runtime.activated != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestContentControllerEnforcesAuthorityOnlyForLocalMutation(t *testing.T) {
	localRuntime := newRecordingContentRuntime()
	localRuntime.beginErr = errors.New("managed policy authority is active")
	localResult := NewContentController(localRuntime).ApplyContent(t.Context(), ContentCommand{Document: "{}", Source: PolicySourceStandalone})
	if localResult.Status != "rejected" || localRuntime.prepared != 0 {
		t.Fatalf("local result=%+v runtime=%+v", localResult, localRuntime)
	}

	managedRuntime := newRecordingContentRuntime()
	managedResult := NewContentController(managedRuntime).ApplyContent(t.Context(), ContentCommand{Document: "{}", Source: PolicySourceManaged})
	if managedResult.Status != "applied" || len(managedRuntime.beginMutations) != 0 || managedRuntime.committed != 1 || managedRuntime.activated != 1 {
		t.Fatalf("managed result=%+v runtime=%+v", managedResult, managedRuntime)
	}
}

func TestContentControllerRejectsMismatchedRequestIdentity(t *testing.T) {
	runtime := newRecordingContentRuntime()
	result := NewContentController(runtime).ApplyContent(t.Context(), ContentCommand{
		Context: RequestContext{TenantID: "other-tenant"}, Document: "{}", Source: PolicySourceManaged,
	})
	if result.Status != "rejected" || !strings.Contains(result.Message, "tenant mismatch") || runtime.prepared != 0 {
		t.Fatalf("result=%+v runtime=%+v", result, runtime)
	}
}

func TestContentControllerTrimsListAndGetKeys(t *testing.T) {
	runtime := newRecordingContentRuntime()
	controller := NewContentController(runtime)
	if _, err := controller.ListContent(t.Context(), "  iocpack  "); err != nil {
		t.Fatal(err)
	}
	if _, _, err := controller.GetContent(t.Context(), "  ioc:feed  "); err != nil {
		t.Fatal(err)
	}
	if runtime.listKind != "iocpack" || runtime.getRef != "ioc:feed" {
		t.Fatalf("list kind=%q get ref=%q", runtime.listKind, runtime.getRef)
	}
}

func newRecordingContentRuntime() *recordingContentRuntime {
	return &recordingContentRuntime{
		identity: ContentIdentity{TenantID: "tenant-a", AgentID: "agent-a"},
		record: agentcontent.Record{
			Ref: "ioc:feed", Kind: "iocpack", Version: "v1", Digest: "sha256:feed", Status: "applied",
		},
		build: ContentDetectionBuild{Report: detection.ApplyReport{Status: "applied"}},
	}
}
