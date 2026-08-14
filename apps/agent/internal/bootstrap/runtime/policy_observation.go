package runtime

import (
	"context"
	"fmt"

	agentpolicy "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/policy"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sqlite"
	agenthealth "github.com/sysarmor/sysarmor-next-project/packages/contracts/health"
	controlplanev1 "github.com/sysarmor/sysarmor-next-project/packages/contracts/proto/controlplane/v1"
)

func (r *Coordinator) pendingPolicyStatus(ctx context.Context) (agenthealth.PendingPolicyStatus, error) {
	if r.localStore == nil {
		return agenthealth.PendingPolicyStatus{}, nil
	}
	record, status, ok, err := r.localStore.DesiredPolicy(ctx, "endpoint", sqlite.PolicySourceManaged)
	if err != nil || !ok {
		return agenthealth.PendingPolicyStatus{}, err
	}
	policy, err := agentpolicy.ParseEndpointPolicy(record.Document)
	if err != nil {
		return agenthealth.PendingPolicyStatus{}, fmt.Errorf("parse pending endpoint policy: %w", err)
	}
	return agenthealth.PendingPolicyStatus{
		Status: string(status), Source: string(sqlite.PolicySourceManaged), PolicyID: policy.PolicyID,
		Version: record.Version, Digest: record.Digest,
	}, nil
}

func pendingPolicyMessage(status agenthealth.PendingPolicyStatus) *controlplanev1.PendingPolicyStatus {
	if status.Status == "" {
		return nil
	}
	return &controlplanev1.PendingPolicyStatus{
		Status: status.Status, Source: status.Source, PolicyId: status.PolicyID,
		Version: status.Version, Digest: status.Digest,
	}
}
