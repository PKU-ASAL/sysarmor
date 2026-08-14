package runtime

import (
	"context"
	"fmt"
	"strings"

	agentcontent "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/content"
	agentcontrol "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/control"
	detectionruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/domain/detection/runtime"
)

type contentApplicationAdapter struct {
	runner *Runtime
}

func newContentApplicationAdapter(runner *Runtime) *contentApplicationAdapter {
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

func (r *contentApplicationAdapter) ValidateContent(document string, allowUnsigned bool) (agentcontrol.ContentRecord, error) {
	record, err := r.runner.contentStore().Apply(document, allowUnsigned, true)
	return contentApplicationRecord(record), err
}

func (r *contentApplicationAdapter) Activate(document string, allowUnsigned bool) (agentcontrol.ContentRecord, agentcontrol.ContentApplyReport, error) {
	var record agentcontent.Record
	var report detectionruntime.ApplyReport
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
	return contentApplicationRecord(record), agentcontrol.ContentApplyReport{Status: report.Status, Warnings: append([]string(nil), report.Warnings...)}, activationErr
}

func (r *contentApplicationAdapter) ListContent(kind string) []agentcontrol.ContentRecord {
	records := r.runner.contentStore().List(kind)
	result := make([]agentcontrol.ContentRecord, 0, len(records))
	for _, record := range records {
		result = append(result, contentApplicationRecord(record))
	}
	return result
}

func (r *contentApplicationAdapter) GetContent(ref string) (agentcontrol.ContentRecord, bool) {
	record, ok := r.runner.contentStore().Get(ref)
	return contentApplicationRecord(record), ok
}

func contentApplicationRecord(record agentcontent.Record) agentcontrol.ContentRecord {
	return agentcontrol.ContentRecord{Ref: record.Ref, Kind: record.Kind, Version: record.Version, Digest: record.Digest, Signed: record.Signed, Status: record.Status, RawJSON: record.RawJSON}
}
