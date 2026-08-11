package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/bootstrap"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":9443", "manager HTTP listen address")
	postgresDriver := flag.String("postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "PostgreSQL database/sql driver name")
	postgresDSN := flag.String("postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "PostgreSQL DSN")
	opensearchURL := flag.String("opensearch-url", envDefault("SYSARMOR_OPENSEARCH_URL", ""), "OpenSearch URL")
	opensearchUsername := flag.String("opensearch-username", envDefault("SYSARMOR_OPENSEARCH_USERNAME", ""), "OpenSearch basic auth username")
	opensearchPassword := flag.String("opensearch-password", envDefault("SYSARMOR_OPENSEARCH_PASSWORD", ""), "OpenSearch basic auth password")
	jwtPublicKey := flag.String("jwt-public-key", envDefault("SYSARMOR_JWT_PUBLIC_KEY_FILE", ""), "trusted BFF RS256 JWT public key PEM")
	jwtIssuer := flag.String("jwt-issuer", envDefault("SYSARMOR_JWT_ISSUER", ""), "required JWT issuer")
	jwtAudience := flag.String("jwt-audience", envDefault("SYSARMOR_JWT_AUDIENCE", ""), "required JWT audience")
	flag.Parse()
	if flag.NArg() > 0 && flag.Arg(0) == "version" {
		fmt.Println(version)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server, closer, err := bootstrap.NewManager(ctx, bootstrap.ManagerConfig{
		ListenAddress: *listen, PostgresDriver: *postgresDriver, PostgresDSN: *postgresDSN,
		OpenSearchURL: *opensearchURL, OpenSearchUsername: *opensearchUsername, OpenSearchPassword: *opensearchPassword,
		JWT:        managerauth.Config{PublicKeyFile: *jwtPublicKey, Issuer: *jwtIssuer, Audience: *jwtAudience},
		Enrollment: bootstrap.EnrollmentHTTPConfig{CACertFile: os.Getenv("SYSARMOR_AGENT_CA_CERT"), CAKeyFile: os.Getenv("SYSARMOR_AGENT_CA_KEY"), TrustDomain: os.Getenv("SYSARMOR_TRUST_DOMAIN"), PublicURL: os.Getenv("SYSARMOR_PUBLIC_URL"), ArtifactPublicKeyFile: os.Getenv("SYSARMOR_ARTIFACT_PUBLIC_KEY"), ArtifactDir: envDefault("SYSARMOR_ARTIFACT_DIR", "/var/lib/sysarmor/manager/artifacts"), DeployGatewayAddress: os.Getenv("SYSARMOR_DEPLOY_GATEWAY_ADDR"), DeployGatewayServerName: os.Getenv("SYSARMOR_DEPLOY_GATEWAY_SNI"), PackageDownloadBaseURL: os.Getenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL")},
		Artifact:   bootstrap.ArtifactConfig{ArtifactPublicKeyFile: os.Getenv("SYSARMOR_ARTIFACT_PUBLIC_KEY"), ArtifactDir: envDefault("SYSARMOR_ARTIFACT_DIR", "/var/lib/sysarmor/manager/artifacts")},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure production manager: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := closer.Close(); err != nil {
			log.Printf("close postgres: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "manager serve: %v\n", err)
		os.Exit(1)
	}
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
