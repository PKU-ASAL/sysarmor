package bootstrap

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	policyhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/policy"
	policypostgres "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/outbound/postgres/policy"
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
	return policyhttp.NewHandler(policyhttp.Options{
		Publish: policyapp.NewPublishService(uow, clock, ids),
		Assign:  policyapp.NewAssignService(uow, clock, ids),
		Save:    policyapp.NewSaveService(uow, clock, ids),
		Query:   policyapp.NewQueryService(uow),
		Resolve: resolve,
	}), nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type uuidGenerator struct{}

func (uuidGenerator) New() string { return uuid.NewString() }
