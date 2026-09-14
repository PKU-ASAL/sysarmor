package runtime

import (
	"context"
	"fmt"

	sensorruntime "github.com/sysarmor/sysarmor-next-project/apps/agent/internal/adapters/sensor/runtime"
	"github.com/sysarmor/sysarmor-next-project/packages/sensor-sdk/contract"
)

type endpointPolicyReconciler struct {
	runtime    sensorruntime.Runtime
	supervisor *sensorruntime.SubscriptionSupervisor
}

func (r endpointPolicyReconciler) Apply(ctx context.Context, intent contract.CollectionIntent) (contract.ApplyResult, error) {
	if r.supervisor != nil {
		if err := r.supervisor.Reconcile(ctx, intent); err != nil {
			return contract.ApplyResult{}, err
		}
		return contract.ApplyResult{State: contract.ApplyStateApplied}, nil
	}
	if r.runtime == nil {
		return contract.ApplyResult{}, fmt.Errorf("sensor runtime is unavailable")
	}
	return r.runtime.Apply(ctx, intent)
}
