package ports

import (
	"context"
	"io"
	"time"

	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

type ArtifactFilter struct {
	Kind   string
	Status domainartifact.Status
}

type ArtifactRepository interface {
	Get(context.Context, tenant.ID, string) (domainartifact.Artifact, error)
	List(context.Context, tenant.ID, ArtifactFilter) ([]domainartifact.Artifact, error)
	Put(context.Context, domainartifact.Artifact) (domainartifact.Artifact, error)
}

type ArtifactChannelRepository interface {
	Get(context.Context, tenant.ID, string) (domainartifact.Channel, error)
	List(context.Context, tenant.ID) ([]domainartifact.Channel, error)
	Put(context.Context, domainartifact.Channel) (domainartifact.Channel, error)
}

type ArtifactTransaction interface {
	Artifacts() ArtifactRepository
	Channels() ArtifactChannelRepository
}

type ArtifactUnitOfWork interface {
	Execute(context.Context, func(context.Context, ArtifactTransaction) error) error
}

type ArtifactArchiveInput struct {
	Name      string
	Kind      string
	Version   string
	OS        string
	Arch      string
	Filename  string
	CreatedBy string
	Content   ArtifactReader
}

type ArtifactReader interface {
	Read([]byte) (int, error)
}

type ArchivedArtifact struct {
	ID          string
	SHA256      string
	SizeBytes   int64
	StoragePath string
	Metadata    map[string]string
}

type ArtifactArchive interface {
	Store(context.Context, tenant.ID, ArtifactArchiveInput) (ArchivedArtifact, error)
	Remove(context.Context, string) error
}

type ArchivedContent struct {
	Content io.ReadSeekCloser
	Name    string
	Size    int64
	ModTime time.Time
}

type ArtifactContentReader interface {
	Open(context.Context, string) (ArchivedContent, error)
}
