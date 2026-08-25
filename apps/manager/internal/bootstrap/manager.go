package bootstrap

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/lib/pq"
	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/auth"
	managerapi "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/manager"
	platformopensearch "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/opensearch"
	postgresmigrations "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/migrations"
)

type ManagerConfig struct {
	ListenAddress      string
	PostgresDriver     string
	PostgresDSN        string
	KafkaBrokers       []string
	OpenSearchURL      string
	OpenSearchUsername string
	OpenSearchPassword string
	JWT                JWTConfig
	Enrollment         EnrollmentHTTPConfig
	Artifact           ArtifactConfig
}

type JWTConfig struct {
	PublicKeyFile string
	Issuer        string
	Audience      string
}

func NewManager(ctx context.Context, config ManagerConfig) (*http.Server, io.Closer, error) {
	if strings.TrimSpace(config.PostgresDSN) == "" {
		return nil, nil, fmt.Errorf("postgres dsn is required")
	}
	if strings.TrimSpace(config.PostgresDriver) == "" {
		return nil, nil, fmt.Errorf("postgres driver is required")
	}
	if strings.TrimSpace(config.PostgresDriver) != "postgres" {
		return nil, nil, fmt.Errorf("postgres driver must be postgres")
	}
	if len(cleanKafkaBrokers(config.KafkaBrokers)) == 0 {
		return nil, nil, fmt.Errorf("kafka brokers are required")
	}
	db, migration, err := openManagerDatabase(ctx, config)
	if err != nil {
		return nil, nil, err
	}
	server, err := buildManagerServer(ctx, db, migration, config)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	snapshots, err := startPolicySnapshotRuntime(db, config.KafkaBrokers)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("start policy snapshot dispatcher: %w", err)
	}
	return server, &managerResources{db: db, snapshot: snapshots}, nil
}

func openManagerDatabase(ctx context.Context, config ManagerConfig) (*sql.DB, postgresmigrations.MigrationResult, error) {
	return OpenPostgres(ctx, config.PostgresDriver, config.PostgresDSN)
}

func OpenPostgres(ctx context.Context, driver, dsn string) (*sql.DB, postgresmigrations.MigrationResult, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, postgresmigrations.MigrationResult{}, fmt.Errorf("postgres dsn is required")
	}
	if strings.TrimSpace(driver) == "" {
		return nil, postgresmigrations.MigrationResult{}, fmt.Errorf("postgres driver is required")
	}
	driver = strings.TrimSpace(driver)
	if driver != "postgres" {
		return nil, postgresmigrations.MigrationResult{}, fmt.Errorf("postgres driver must be postgres")
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, postgresmigrations.MigrationResult{}, fmt.Errorf("open postgres: %w", err)
	}
	migration, err := postgresmigrations.ApplyMigrations(ctx, db)
	if err != nil {
		_ = db.Close()
		return nil, postgresmigrations.MigrationResult{}, err
	}
	return db, migration, nil
}

func buildManagerServer(ctx context.Context, db *sql.DB, migration postgresmigrations.MigrationResult, config ManagerConfig) (*http.Server, error) {
	searcher, err := platformopensearch.NewHTTPIndexerWithAuth(config.OpenSearchURL, config.OpenSearchUsername, config.OpenSearchPassword)
	if err != nil {
		return nil, fmt.Errorf("open opensearch searcher: %w", err)
	}
	verifier, err := managerauth.NewVerifier(ctx, managerauth.Config{
		PublicKeyFile: config.JWT.PublicKeyFile,
		Issuer:        config.JWT.Issuer,
		Audience:      config.JWT.Audience,
	})
	if err != nil {
		return nil, fmt.Errorf("configure JWT verifier: %w", err)
	}
	routes, err := composeManagerRoutes(ctx, db, searcher, migration, config)
	if err != nil {
		return nil, err
	}
	return managerHTTPServer(config.ListenAddress, routes.HandlerWithAuth(verifier)), nil
}

func composeManagerRoutes(ctx context.Context, db *sql.DB, searcher *platformopensearch.HTTPIndexer, migration postgresmigrations.MigrationResult, config ManagerConfig) (*managerapi.Server, error) {
	server := managerapi.NewServerWithSearch(searcher)
	if err := setManagerQueryRoutes(server, db, searcher, migration); err != nil {
		return nil, err
	}
	if err := setManagerCommandRoutes(ctx, server, db, searcher, config); err != nil {
		return nil, err
	}
	return server, nil
}

func setManagerQueryRoutes(server *managerapi.Server, db *sql.DB, searcher *platformopensearch.HTTPIndexer, migration postgresmigrations.MigrationResult) error {
	resolve := managerapi.PolicyRequestContext
	telemetry, err := NewManagerTelemetryHTTP(searcher, resolve)
	if err != nil {
		return fmt.Errorf("configure telemetry application: %w", err)
	}
	search, err := NewManagerSearchHTTP(searcher, resolve)
	if err != nil {
		return fmt.Errorf("configure search application: %w", err)
	}
	policy, err := NewManagerPolicyHTTP(db, resolve)
	if err != nil {
		return fmt.Errorf("configure policy application: %w", err)
	}
	identity, err := NewManagerIdentityHTTP(db, resolve)
	if err != nil {
		return fmt.Errorf("configure identity application: %w", err)
	}
	server.SetTelemetryRoutes(telemetry)
	server.SetSearchRoutes(search)
	server.SetPolicyRoutes(policy)
	server.SetIdentityRoutes(identity)
	return setManagerOverviewRoutes(server, db, searcher, migration)
}

func setManagerOverviewRoutes(server *managerapi.Server, db *sql.DB, searcher *platformopensearch.HTTPIndexer, migration postgresmigrations.MigrationResult) error {
	resolve := managerapi.PolicyRequestContext
	identity, err := NewManagerIdentityQueries(db)
	if err != nil {
		return fmt.Errorf("configure identity queries: %w", err)
	}
	analysis, err := NewManagerAnalysisHTTP(db, searcher, resolve)
	if err != nil {
		return fmt.Errorf("configure analysis application: %w", err)
	}
	status := managerStorageStatus(migration)
	overview, err := NewManagerOverviewHTTP(identity, searcher, status, resolve)
	if err != nil {
		return fmt.Errorf("configure overview application: %w", err)
	}
	server.SetAnalysisRoutes(analysis)
	server.SetStatusRoutes(NewManagerStatusHTTP(ManagerStatus{Backend: status.Backend, StateVersion: status.StateVersion,
		MigrationVersion: status.MigrationVersion, PostgresSchemaVersion: status.PostgresSchemaVersion}))
	server.SetOverviewRoutes(overview)
	return nil
}

func setManagerCommandRoutes(ctx context.Context, server *managerapi.Server, db *sql.DB, searcher *platformopensearch.HTTPIndexer, config ManagerConfig) error {
	resolve := managerapi.PolicyRequestContext
	enrollmentConfig := config.Enrollment
	enrollmentConfig.DB, enrollmentConfig.Resolve = db, resolve
	enrollment, err := NewManagerEnrollmentHTTP(enrollmentConfig)
	if err != nil {
		return fmt.Errorf("configure enrollment application: %w", err)
	}
	control, err := NewManagerControlHTTP(db, resolve)
	if err != nil {
		return fmt.Errorf("configure control application: %w", err)
	}
	response, err := NewManagerResponseHTTP(db, searcher, resolve)
	if err != nil {
		return fmt.Errorf("configure response application: %w", err)
	}
	artifactConfig := config.Artifact
	artifactConfig.DB, artifactConfig.Resolve = db, resolve
	artifact, err := NewManagerArtifact(artifactConfig)
	if err != nil {
		return fmt.Errorf("configure artifact application: %w", err)
	}
	if err := artifact.Feed.SeedFromEnv(ctx); err != nil {
		log.Printf("seed package index: %v", err)
	}
	server.SetEnrollmentRoutes(enrollment)
	server.SetControlRoutes(control)
	server.SetResponseRoutes(response)
	server.SetArtifactRoutes(artifact.Routes)
	return nil
}

func managerStorageStatus(migration postgresmigrations.MigrationResult) ManagerStorageStatus {
	return ManagerStorageStatus{Backend: "postgres", StateVersion: 1, MigrationVersion: migration.Version,
		PostgresSchemaVersion: postgresmigrations.PostgresVersion}
}

func managerHTTPServer(listen string, handler http.Handler) *http.Server {
	if strings.TrimSpace(listen) == "" {
		listen = ":9443"
	}
	return &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
}
