package bootstrap

import (
	"context"
	"net/http"
	"strings"
	"testing"

	overviewhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/overview"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainidentity "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/identity"
)

func TestNewManagerOverviewHTTPValidatesDependencies(t *testing.T) {
	queries := &overviewQueriesStub{}
	searcher := telemetryBootstrapSearcher{}
	resolve := func(*http.Request) (managerapp.RequestContext, error) { return managerapp.RequestContext{}, nil }
	status := ManagerStorageStatus{Backend: "postgres", PostgresSchemaVersion: 6}
	for name, test := range map[string]func() error{
		"identity":  func() error { _, err := NewManagerOverviewHTTP(nil, searcher, status, resolve); return err },
		"telemetry": func() error { _, err := NewManagerOverviewHTTP(queries, nil, status, resolve); return err },
		"resolver":  func() error { _, err := NewManagerOverviewHTTP(queries, searcher, status, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := test(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestNewManagerOverviewHTTPBuildsHandler(t *testing.T) {
	queries := &overviewQueriesStub{}
	handler, err := NewManagerOverviewHTTP(queries, telemetryBootstrapSearcher{},
		ManagerStorageStatus{Backend: "postgres", PostgresSchemaVersion: 6},
		func(*http.Request) (managerapp.RequestContext, error) { return managerapp.RequestContext{}, nil })
	if err != nil || handler == nil {
		t.Fatalf("handler=%v error=%v", handler, err)
	}
	var _ *overviewhttp.Handler = handler
}

type overviewQueriesStub struct{}

func (*overviewQueriesStub) AgentOverview(context.Context, managerapp.RequestContext) (domainidentity.AgentOverview, error) {
	return domainidentity.AgentOverview{}, nil
}

func (*overviewQueriesStub) Metrics(context.Context, managerapp.RequestContext) (domainidentity.Metrics, error) {
	return domainidentity.Metrics{}, nil
}
