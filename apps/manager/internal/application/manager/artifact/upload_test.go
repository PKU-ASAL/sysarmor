package artifact

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

func TestUploadArchivesWithAuthenticatedTenantAndActor(t *testing.T) {
	archive := &artifactArchiveStub{stored: ports.ArchivedArtifact{
		ID: "artifact-a", SHA256: "sha256-a", SizeBytes: 42, StoragePath: "/archive/artifact-a.tar.gz",
	}}
	repository := &artifactRepositoryStub{}
	service := NewServiceWithArchive(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: repository, channels: &channelRepositoryStub{},
	}}, archive, artifactClockStub{now: time.Unix(200, 0).UTC()})

	result, err := service.Upload(context.Background(), artifactOperatorRequest(t), UploadCommand{
		Name: "sysarmor-agent", Kind: "bundle", Version: "1.0.0", Filename: "agent.tar.gz",
		Content: strings.NewReader("archive"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if archive.tenantID != tenant.ID("tenant-a") || archive.input.CreatedBy != "operator-a" {
		t.Fatalf("tenant=%q input=%+v", archive.tenantID, archive.input)
	}
	if result.ID != "artifact-a" || result.StoragePath == "" || repository.puts != 1 {
		t.Fatalf("result=%+v puts=%d", result, repository.puts)
	}
}

func TestUploadRemovesArchiveWhenPersistenceFails(t *testing.T) {
	persistErr := errors.New("database unavailable")
	archive := &artifactArchiveStub{stored: ports.ArchivedArtifact{
		ID: "artifact-a", SHA256: "sha256-a", StoragePath: "/archive/artifact-a.tar.gz",
	}}
	service := NewServiceWithArchive(&artifactUnitOfWorkStub{tx: artifactTransactionStub{
		artifacts: &failingArtifactRepository{err: persistErr}, channels: &channelRepositoryStub{},
	}}, archive, artifactClockStub{now: time.Unix(200, 0).UTC()})

	_, err := service.Upload(context.Background(), artifactOperatorRequest(t), UploadCommand{
		Name: "sysarmor-agent", Kind: "bundle", Version: "1.0.0", Content: strings.NewReader("archive"),
	})
	if !errors.Is(err, persistErr) || archive.removed != "/archive/artifact-a.tar.gz" {
		t.Fatalf("error=%v removed=%q", err, archive.removed)
	}
}

type artifactArchiveStub struct {
	tenantID tenant.ID
	input    ports.ArtifactArchiveInput
	stored   ports.ArchivedArtifact
	removed  string
}

func (stub *artifactArchiveStub) Store(_ context.Context, tenantID tenant.ID, input ports.ArtifactArchiveInput) (ports.ArchivedArtifact, error) {
	stub.tenantID, stub.input = tenantID, input
	return stub.stored, nil
}

func (stub *artifactArchiveStub) Remove(_ context.Context, path string) error {
	stub.removed = path
	return nil
}

type failingArtifactRepository struct{ err error }

func (repository *failingArtifactRepository) Get(context.Context, tenant.ID, string) (domainartifact.Artifact, error) {
	return domainartifact.Artifact{}, repository.err
}

func (repository *failingArtifactRepository) List(context.Context, tenant.ID, ports.ArtifactFilter) ([]domainartifact.Artifact, error) {
	return nil, repository.err
}

func (repository *failingArtifactRepository) Put(context.Context, domainartifact.Artifact) (domainartifact.Artifact, error) {
	return domainartifact.Artifact{}, repository.err
}
