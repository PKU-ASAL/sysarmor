package bootstrap

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	policyhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/policy"
	controlpostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/control"
	identitypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/identity"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
	controlapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/control"
	identityapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/identity"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
)

func NewManagerPolicyHTTP(db *sql.DB, resolve policyhttp.RequestContextResolver) (*policyhttp.Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("manager policy database is required")
	}
	if resolve == nil {
		return nil, fmt.Errorf("manager policy request context resolver is required")
	}
	uow := policypostgres.NewUnitOfWork(db)
	clock, ids := systemClock{}, uuidGenerator{}
	queries := policyapp.NewQueryService(uow)
	rollouts := policyapp.NewRolloutService(identityapp.NewQueryService(identitypostgres.NewRepositories(db)), queries,
		controlapp.NewQueryService(controlpostgres.NewUnitOfWork(db)))
	return policyhttp.NewHandler(policyhttp.Options{
		Publish: policyapp.NewPublishService(uow, clock, ids),
		Assign:  policyapp.NewAssignService(uow, clock, ids),
		Save:    policyapp.NewSaveService(uow, clock, ids),
		Query:   queries,
		Rollout: rollouts,
		Resolve: resolve,
	}), nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type uuidGenerator struct{}

func (uuidGenerator) New() string { return uuid.NewString() }
