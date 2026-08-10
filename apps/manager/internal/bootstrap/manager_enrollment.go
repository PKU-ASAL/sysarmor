package bootstrap

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	enrollmenthttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/enrollment"
	certificateadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/certificate"
	enrollmenttoken "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/enrollmenttoken"
	enrollmentpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/enrollment"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
)

type EnrollmentHTTPConfig struct {
	DB                      *sql.DB
	CACertFile              string
	CAKeyFile               string
	TrustDomain             string
	PublicURL               string
	ArtifactPublicKeyFile   string
	ArtifactDir             string
	DeployGatewayAddress    string
	DeployGatewayServerName string
	PackageDownloadBaseURL  string
	Resolve                 enrollmenthttp.RequestContextResolver
}

func NewManagerEnrollmentHTTP(config EnrollmentHTTPConfig) (*enrollmenthttp.Handler, error) {
	if config.DB == nil {
		return nil, fmt.Errorf("enrollment postgres database is required")
	}
	if config.Resolve == nil {
		return nil, fmt.Errorf("enrollment request context resolver is required")
	}
	certificatePEM, err := readEnrollmentFile("agent CA certificate", config.CACertFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readEnrollmentFile("agent CA key", config.CAKeyFile)
	if err != nil {
		return nil, err
	}
	issuer, err := certificateadapter.NewIssuer(certificatePEM, keyPEM, defaultTrustDomain(config.TrustDomain))
	if err != nil {
		return nil, fmt.Errorf("configure enrollment certificate issuer: %w", err)
	}
	artifactPublicKey, err := readEnrollmentFile("artifact public key", config.ArtifactPublicKeyFile)
	if err != nil {
		return nil, err
	}
	uow := enrollmentpostgres.NewUnitOfWork(config.DB)
	tokens := enrollmenttoken.NewGenerator()
	service := enrollmentapp.NewIssueService(uow, issuer, systemClock{})
	completion := enrollmentapp.NewCompletionService(uow, systemClock{})
	create := enrollmentapp.NewCreateService(uow, tokens, systemClock{}, uuidGenerator{})
	query := enrollmentapp.NewQueryService(uow)
	bootstrap := enrollmentapp.NewBootstrapService(uow, tokens, systemClock{})
	artifact := enrollmentapp.NewArtifactService(uow, systemClock{})
	renderer := enrollmenthttp.NewInstallScriptRenderer(artifactPublicKey, config.PublicURL)
	return enrollmenthttp.NewHandler(enrollmenthttp.Options{
		Create: create, Query: query, DeploymentQuery: query, Bootstrap: bootstrap, InstallScript: renderer,
		Artifact: artifact, Issue: service, Completion: completion, Resolve: config.Resolve,
		PublicURL: config.PublicURL, ArtifactDir: config.ArtifactDir,
		DeployGatewayAddress:    defaultBootstrapString(config.DeployGatewayAddress, "127.0.0.1:19444"),
		DeployGatewayServerName: config.DeployGatewayServerName, PackageDownloadBaseURL: config.PackageDownloadBaseURL,
	}), nil
}

func defaultBootstrapString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func readEnrollmentFile(name, path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%s file is required", name)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("%s is empty", name)
	}
	return value, nil
}

func defaultTrustDomain(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return "sysarmor.local"
}
