package daemon

import (
	"context"

	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/content"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
)

type contentRuntime struct {
	runner *AgentRuntime
}

func newContentRuntime(runner *AgentRuntime) *contentRuntime {
	return &contentRuntime{runner: runner}
}

func (r *contentRuntime) ContentIdentity() agentcontrol.ContentIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.ContentIdentity{
		TenantID: identity.TenantID,
		AgentID:  identity.AgentID,
	}
}

func (r *contentRuntime) BeginLocalContentMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *contentRuntime) ValidateContentContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *contentRuntime) ValidateContent(document string, allowUnsigned bool) (agentcontent.Record, error) {
	return r.runner.contentStore().Apply(document, allowUnsigned, true)
}

func (r *contentRuntime) WithContentTransaction(run func()) {
	r.runner.withDetectionUpdateTransaction(run)
}

func (r *contentRuntime) PrepareContent(document string, allowUnsigned bool) (agentcontent.Record, agentcontent.Snapshot, error) {
	return r.runner.contentStore().Prepare(document, allowUnsigned)
}

func (r *contentRuntime) BuildContentDetection(snapshot agentcontent.Snapshot) agentcontrol.ContentDetectionBuild {
	engine, report := r.runner.buildDetectionWithSnapshot(snapshot)
	return agentcontrol.ContentDetectionBuild{Engine: engine, Report: report}
}

func (r *contentRuntime) RecordRejectedContentDetection(report detection.ApplyReport) {
	r.runner.setDetectionStatus(r.runner.activePolicy(), report, r.runner.contentStore().Snapshot())
}

func (r *contentRuntime) CommitContent(record agentcontent.Record) error {
	return r.runner.contentStore().Commit(record)
}

func (r *contentRuntime) ActivateContentDetection(snapshot agentcontent.Snapshot, build agentcontrol.ContentDetectionBuild) {
	r.runner.setDetection(build.Engine)
	r.runner.setDetectionStatus(r.runner.activePolicy(), build.Report, snapshot)
}

func (r *contentRuntime) ListContent(kind string) []agentcontent.Record {
	return r.runner.contentStore().List(kind)
}

func (r *contentRuntime) GetContent(ref string) (agentcontent.Record, bool) {
	return r.runner.contentStore().Get(ref)
}
