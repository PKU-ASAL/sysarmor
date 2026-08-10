package bootstrap

import (
	"database/sql"
	"fmt"

	identityhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/identity"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
)

func NewManagerIdentityHTTP(db *sql.DB, resolve identityhttp.RequestContextResolver) (*identityhttp.Handler, error) {
	queries, err := NewManagerIdentityQueries(db)
	if err != nil {
		return nil, err
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager identity request context resolver is required")
	}
	commands := identityapp.NewCommandService(identitypostgres.NewHealthWriter(db))
	return identityhttp.NewHandler(identityhttp.Options{Query: queries, Commands: commands, Resolve: resolve}), nil
}

func NewManagerIdentityQueries(db *sql.DB) (*identityapp.QueryService, error) {
	if db == nil {
		return nil, fmt.Errorf("manager identity database is required")
	}
	return identityapp.NewQueryService(identitypostgres.NewRepositories(db)), nil
}
