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
	policy *policyRuntime
}

func newContentApplicationAdapter(policy *policyRuntime) *contentApplicationAdapter {
	return &contentApplicationAdapter{policy: policy}
}

func (r *contentApplicationAdapter) ContentIdentity() agentcontrol.ContentIdentity {
	identity := r.policy.management.currentIdentity()
	return agentcontrol.ContentIdentity{
		TenantID: identity.TenantID,
		AgentID:  identity.AgentID,
	}
}

func (r *contentApplicationAdapter) BeginLocalContentMutation(ctx context.Context, mutation bool) (func(), error) {
	return r.policy.beginLocalPolicyMutation(ctx, mutation)
}

func (r *contentApplicationAdapter) ValidateContentContext(ctx agentcontrol.RequestContext) error {
	return r.policy.management.validateControlIdentity(ctx.TenantID, ctx.AgentID)
}

func (r *contentApplicationAdapter) ValidateContent(document string, allowUnsigned bool) (agentcontrol.ContentRecord, error) {
	record, err := r.policy.contentStore().Apply(document, allowUnsigned, true)
	return contentApplicationRecord(record), err
}

func (r *contentApplicationAdapter) Activate(document string, allowUnsigned bool) (agentcontrol.ContentRecord, agentcontrol.ContentApplyReport, error) {
	var record agentcontent.Record
	var report detectionruntime.ApplyReport
	var activationErr error
	r.policy.withDetectionUpdateTransaction(func() {
		var snapshot agentcontent.Snapshot
		record, snapshot, activationErr = r.policy.contentStore().Prepare(document, allowUnsigned)
		if activationErr != nil {
			return
		}
		engine, buildReport := r.policy.buildDetectionWithSnapshot(snapshot)
		report = buildReport
		if buildReport.Status == "rejected" {
			r.policy.setDetectionStatus(r.policy.activePolicy(), buildReport, r.policy.contentStore().Snapshot())
			activationErr = fmt.Errorf("content rejected; detection rebuild failed: %s", strings.Join(buildReport.Details, "; "))
			return
		}
		if activationErr = r.policy.contentStore().Commit(record); activationErr != nil {
			return
		}
		r.policy.setDetection(engine)
		r.policy.setDetectionStatus(r.policy.activePolicy(), buildReport, snapshot)
	})
	return contentApplicationRecord(record), agentcontrol.ContentApplyReport{Status: report.Status, Warnings: append([]string(nil), report.Warnings...)}, activationErr
}

func (r *contentApplicationAdapter) ListContent(kind string) []agentcontrol.ContentRecord {
	records := r.policy.contentStore().List(kind)
	result := make([]agentcontrol.ContentRecord, 0, len(records))
	for _, record := range records {
		result = append(result, contentApplicationRecord(record))
	}
	return result
}

func (r *contentApplicationAdapter) GetContent(ref string) (agentcontrol.ContentRecord, bool) {
	record, ok := r.policy.contentStore().Get(ref)
	return contentApplicationRecord(record), ok
}

func contentApplicationRecord(record agentcontent.Record) agentcontrol.ContentRecord {
	return agentcontrol.ContentRecord{Ref: record.Ref, Kind: record.Kind, Version: record.Version, Digest: record.Digest, Signed: record.Signed, Status: record.Status, RawJSON: record.RawJSON}
}
