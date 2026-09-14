package bootstrap

import (
	"database/sql"
	"fmt"
	"strings"

	artifactfeed "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/feed"
	artifacthttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/artifact"
	artifactarchive "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/archive"
	artifactpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/artifact"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
)

type ArtifactConfig struct {
	DB                    *sql.DB
	ArtifactDir           string
	ArtifactPublicKeyFile string
	Resolve               artifacthttp.RequestContextResolver
}

type ManagerArtifact struct {
	Routes *artifacthttp.Handler
	Feed   *artifactfeed.ArtifactSeeder
}

func NewManagerArtifact(config ArtifactConfig) (*ManagerArtifact, error) {
	if config.DB == nil {
		return nil, fmt.Errorf("artifact postgres database is required")
	}
	if config.Resolve == nil {
		return nil, fmt.Errorf("artifact request context resolver is required")
	}
	if strings.TrimSpace(config.ArtifactDir) == "" {
		return nil, fmt.Errorf("artifact archive directory is required")
	}
	publicKey, err := readEnrollmentFile("artifact public key", config.ArtifactPublicKeyFile)
	if err != nil {
		return nil, err
	}
	archive := artifactarchive.NewArtifactArchive(config.ArtifactDir, publicKey)
	service := artifactapp.NewServiceWithArchive(artifactpostgres.NewUnitOfWork(config.DB), archive, systemClock{})
	return &ManagerArtifact{
		Routes: artifacthttp.NewHandler(artifacthttp.Options{Service: service, Content: archive, Resolve: config.Resolve}),
		Feed:   artifactfeed.NewArtifactSeeder(service, nil),
	}, nil
}
