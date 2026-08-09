package ingestworker

import (
	"context"

	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type storeRarityReader struct{ store store.RarityReader }

func (reader storeRarityReader) Rarity(ctx context.Context, tenantID tenant.ID) (domainidentity.RarityBaseline, error) {
	return reader.store.Rarity(ctx, tenantID)
}
