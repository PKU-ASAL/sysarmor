package worker

import (
	"context"
	"fmt"

	contractmapper "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/contracts"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type BatchProjector struct{ indexer ports.DocumentProjector }

func NewBatchProjector(indexer ports.DocumentProjector) *BatchProjector {
	return &BatchProjector{indexer: indexer}
}

func (projector *BatchProjector) Project(ctx context.Context, projection ports.BatchProjection) error {
	if projector == nil || projector.indexer == nil {
		return fmt.Errorf("batch projector requires indexer")
	}
	documents, err := projectionDocuments(projection)
	if err != nil {
		return err
	}
	err = projector.indexer.BulkIndex(ctx, documents)
	if platformopensearch.ErrorClassOf(err) == platformopensearch.ErrorPermanent {
		return contractmapper.PermanentMessage(projection.Source, "permanent_projection", err)
	}
	return err
}
