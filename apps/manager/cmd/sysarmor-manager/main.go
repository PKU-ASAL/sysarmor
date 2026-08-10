package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/api"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/bootstrap"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store/backend"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":9443", "manager HTTP listen address")
	storeBackend := flag.String("store-backend", backend.KindPostgres, "store backend: postgres")
	storePath := flag.String("store", "", "deprecated: file store path is not used by product backends")
	postgresDriver := flag.String("postgres-driver", envDefault("SYSARMOR_POSTGRES_DRIVER", "postgres"), "database/sql driver name for postgres backend")
	postgresDSN := flag.String("postgres-dsn", envDefault("SYSARMOR_POSTGRES_DSN", ""), "Postgres DSN for postgres backend")
	opensearchURL := flag.String("opensearch-url", envDefault("SYSARMOR_OPENSEARCH_URL", ""), "OpenSearch URL for searchable telemetry")
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
	if *storeBackend == backend.KindFile {
		fmt.Fprintln(os.Stderr, "open store: file backend has been removed from the sysarmor-manager product path; use postgres")
		os.Exit(1)
	}
	verifier, err := managerauth.NewVerifier(ctx, managerauth.Config{
		PublicKeyFile: *jwtPublicKey, Issuer: *jwtIssuer, Audience: *jwtAudience,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure JWT verifier: %v\n", err)
		os.Exit(1)
	}
	storeResult, err := backend.Open(ctx, backend.Options{
		Kind:           *storeBackend,
		Path:           *storePath,
		PostgresDriver: *postgresDriver,
		PostgresDSN:    *postgresDSN,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := storeResult.Close(); err != nil {
			log.Printf("close store backend: %v", err)
		}
	}()
	st := storeResult.Store
	var searcher platformopensearch.Searcher
	if strings.TrimSpace(*opensearchURL) != "" {
		searcher, err = platformopensearch.NewHTTPIndexerWithAuth(*opensearchURL, *opensearchUsername, *opensearchPassword)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open opensearch searcher: %v\n", err)
			os.Exit(1)
		}
	}
	managerSrv, err := managerServerForBackend(*storeBackend, st, searcher)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure production manager: %v\n", err)
		os.Exit(1)
	}
	policyRoutes, err := bootstrap.NewManagerPolicyHTTP(storeResult.DB, managerapi.PolicyRequestContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure policy application: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetPolicyRoutes(policyRoutes)
	identityRoutes, err := bootstrap.NewManagerIdentityHTTP(storeResult.DB, managerapi.PolicyRequestContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure identity application: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetIdentityRoutes(identityRoutes)
	identityQueries, err := bootstrap.NewManagerIdentityQueries(storeResult.DB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure identity queries: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetIdentityApplication(identityQueries, managerapi.PolicyRequestContext)
	enrollmentRoutes, err := bootstrap.NewManagerEnrollmentHTTP(managerEnrollmentConfig(storeResult.DB))
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure enrollment application: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetEnrollmentRoutes(enrollmentRoutes)
	controlRoutes, err := bootstrap.NewManagerControlHTTP(storeResult.DB, managerapi.PolicyRequestContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure control application: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetControlRoutes(controlRoutes)
	controlQueries, err := bootstrap.NewManagerControlQueries(storeResult.DB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure control queries: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetControlApplication(controlQueries)
	responseRoutes, err := bootstrap.NewManagerResponseHTTP(storeResult.DB, searcher, managerapi.PolicyRequestContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configure response application: %v\n", err)
		os.Exit(1)
	}
	managerSrv.SetResponseRoutes(responseRoutes)
	if err := managerSrv.SeedArtifactFeedFromEnv(ctx); err != nil {
		log.Printf("seed package index: %v", err)
	}

	srv := newManagerHTTPServer(*listen, managerSrv.HandlerWithAuth(verifier))
	log.Printf("sysarmor-manager listening on %s store_backend=%s store=%s", *listen, *storeBackend, *storePath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "manager serve: %v\n", err)
		os.Exit(1)
	}
}

func managerEnrollmentConfig(db *sql.DB) bootstrap.EnrollmentHTTPConfig {
	return bootstrap.EnrollmentHTTPConfig{
		DB: db, CACertFile: os.Getenv("SYSARMOR_AGENT_CA_CERT"), CAKeyFile: os.Getenv("SYSARMOR_AGENT_CA_KEY"),
		TrustDomain: os.Getenv("SYSARMOR_TRUST_DOMAIN"), PublicURL: os.Getenv("SYSARMOR_PUBLIC_URL"),
		ArtifactPublicKeyFile:   os.Getenv("SYSARMOR_ARTIFACT_PUBLIC_KEY"),
		ArtifactDir:             envDefault("SYSARMOR_ARTIFACT_DIR", "/var/lib/sysarmor/manager/artifacts"),
		DeployGatewayAddress:    os.Getenv("SYSARMOR_DEPLOY_GATEWAY_ADDR"),
		DeployGatewayServerName: os.Getenv("SYSARMOR_DEPLOY_GATEWAY_SNI"),
		PackageDownloadBaseURL:  os.Getenv("SYSARMOR_AGENT_PACKAGE_DOWNLOAD_BASE_URL"), Resolve: managerapi.PolicyRequestContext,
	}
}

func managerServerForBackend(kind string, st managerapi.ManagerStore, searcher platformopensearch.Searcher) (*managerapi.Server, error) {
	if kind == backend.KindMemory {
		return managerapi.NewServerWithSearch(st, searcher), nil
	}
	return managerapi.NewProductionServerWithSearch(st, searcher)
}

func newManagerHTTPServer(listen string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
