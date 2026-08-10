package bootstrap

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	enrollmenthttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/enrollment"
	certificateadapter "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/certificate"
	enrollmentpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/enrollment"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
)

type EnrollmentHTTPConfig struct {
	DB          *sql.DB
	CACertFile  string
	CAKeyFile   string
	TrustDomain string
}

func NewManagerEnrollmentHTTP(config EnrollmentHTTPConfig) (*enrollmenthttp.Handler, error) {
	if config.DB == nil {
		return nil, fmt.Errorf("enrollment postgres database is required")
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
	service := enrollmentapp.NewIssueService(enrollmentpostgres.NewUnitOfWork(config.DB), issuer, systemClock{})
	return enrollmenthttp.NewHandler(service), nil
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
