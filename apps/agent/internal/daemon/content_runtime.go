package daemon

import (
	"context"
	"fmt"
	"strings"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	detection "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/detection"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/control"
)

type contentApplicationAdapter struct {
	runner *AgentRuntime
}

func newContentApplicationAdapter(runner *AgentRuntime) *contentApplicationAdapter {
	return &contentApplicationAdapter{runner: runner}
}

func (r *contentApplicationAdapter) ContentIdentity() agentcontrol.ContentIdentity {
	identity := r.runner.currentIdentity()
	return agentcontrol.ContentIdentity{
		TenantID: identity.TenantID,
		AgentID:  identity.AgentID,
	}
}

func (r *contentApplicationAdapter) BeginLocalContentMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.runner.beginLocalPolicyMutation(ctx, mutation)
}

func (r *contentApplicationAdapter) ValidateContentContext(ctx agentcontrol.RequestContext) error {
	return r.runner.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *contentApplicationAdapter) ValidateContent(document string, allowUnsigned bool) (agentcontent.Record, error) {
	return r.runner.contentStore().Apply(document, allowUnsigned, true)
}

func (r *contentApplicationAdapter) Activate(document string, allowUnsigned bool) (agentcontent.Record, detection.ApplyReport, error) {
	var record agentcontent.Record
	var report detection.ApplyReport
	var activationErr error
	r.runner.withDetectionUpdateTransaction(func() {
		var snapshot agentcontent.Snapshot
		record, snapshot, activationErr = r.runner.contentStore().Prepare(document, allowUnsigned)
		if activationErr != nil {
			return
		}
		engine, buildReport := r.runner.buildDetectionWithSnapshot(snapshot)
		report = buildReport
		if buildReport.Status == "rejected" {
			r.runner.setDetectionStatus(r.runner.activePolicy(), buildReport, r.runner.contentStore().Snapshot())
			activationErr = fmt.Errorf("content rejected; detection rebuild failed: %s", strings.Join(buildReport.Details, "; "))
			return
		}
		if activationErr = r.runner.contentStore().Commit(record); activationErr != nil {
			return
		}
		r.runner.setDetection(engine)
		r.runner.setDetectionStatus(r.runner.activePolicy(), buildReport, snapshot)
	})
	return record, report, activationErr
}

func (r *contentApplicationAdapter) ListContent(kind string) []agentcontent.Record {
	return r.runner.contentStore().List(kind)
}

func (r *contentApplicationAdapter) GetContent(ref string) (agentcontent.Record, bool) {
	return r.runner.contentStore().Get(ref)
}
