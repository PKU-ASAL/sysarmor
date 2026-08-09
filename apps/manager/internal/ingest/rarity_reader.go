package ingestworker

import (
	"context"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type storeRarityReader struct{ store *store.Store }

func (reader storeRarityReader) Rarity(_ context.Context, tenantID tenant.ID) (domainidentity.RarityBaseline, error) {
	value, err := reader.store.RarityBaselineSnapshotForTenantWithError(tenantID.String())
	if err != nil {
		return domainidentity.RarityBaseline{}, err
	}
	return domainidentity.RarityBaseline{WorkloadCounts: value.WorkloadCounts}, nil
}
