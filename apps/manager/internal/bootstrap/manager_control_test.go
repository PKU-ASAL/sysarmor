package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	controlhttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/control"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	policyapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/policy"
	domainpolicy "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/policy"
)

func TestNewManagerControlHTTPRequiresDatabaseAndResolver(t *testing.T) {
	if _, err := NewManagerControlHTTP(nil, func(*http.Request) (managerapp.RequestContext, error) {
		return managerapp.RequestContext{}, nil
	}); err == nil || !strings.Contains(err.Error(), "database") {
		t.Fatalf("nil database error = %v", err)
	}
	if _, err := NewManagerControlHTTP(&sql.DB{}, controlhttp.RequestContextResolver(nil)); err == nil || !strings.Contains(err.Error(), "resolver") {
		t.Fatalf("nil resolver error = %v", err)
	}
}

func TestPolicyPayloadResolverReturnsDownlinkDocument(t *testing.T) {
	resolver := policyPayloadResolver{query: policyQueryStub{result: policyapp.GetPolicyResult{Policy: domainpolicy.Policy{
		ID: "policy-a", Version: 3, Document: []byte(`{"manager":true}`),
		DownlinkDocument: []byte(`{"policy_id":"policy-a","version":3}`),
	}}}}

	payload, id, version, err := resolver.Resolve(context.Background(), managerapp.RequestContext{}, "policy-a", 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"policy_id":"policy-a","version":3}` || id != "policy-a" || version != 3 {
		t.Fatalf("payload=%s id=%q version=%d", payload, id, version)
	}
}

type policyQueryStub struct{ result policyapp.GetPolicyResult }

func (stub policyQueryStub) GetPolicy(context.Context, managerapp.RequestContext, policyapp.GetPolicyQuery) (policyapp.GetPolicyResult, error) {
	return stub.result, nil
}
