package telemetry

import (
	"context"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	domaintelemetry "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/telemetry"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestSearchUsesAuthenticatedTenant(t *testing.T) {
	reader := &telemetrySearchReaderStub{documents: []domaintelemetry.IndexedDocument{{
		Index: domaintelemetry.IndexEvents, Document: []byte(`{"id":"event-a"}`),
	}}}
	service := NewSearchService(reader)
	result, err := service.Search(context.Background(), telemetryViewerRequest(t), SearchQuery{
		Indexes: []domaintelemetry.Index{domaintelemetry.IndexEvents}, Query: "shell", Limit: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || reader.tenantID != tenant.ID("tenant-a") || reader.filter.Query != "shell" {
		t.Fatalf("result=%+v tenant=%q filter=%+v", result, reader.tenantID, reader.filter)
	}
}

func TestSearchRejectsUnsupportedIndex(t *testing.T) {
	service := NewSearchService(&telemetrySearchReaderStub{})
	_, err := service.Search(context.Background(), telemetryViewerRequest(t), SearchQuery{
		Indexes: []domaintelemetry.Index{"arbitrary-index"},
	})
	if failure.KindOf(err) != failure.InvalidArgument {
		t.Fatalf("kind=%v error=%v", failure.KindOf(err), err)
	}
}

type telemetrySearchReaderStub struct {
	tenantID  tenant.ID
	filter    ports.TelemetrySearchFilter
	documents []domaintelemetry.IndexedDocument
}

func (stub *telemetrySearchReaderStub) Search(_ context.Context, tenantID tenant.ID, filter ports.TelemetrySearchFilter) ([]domaintelemetry.IndexedDocument, error) {
	stub.tenantID, stub.filter = tenantID, filter
	return stub.documents, nil
}
