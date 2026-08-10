package managerapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func TestControlRoutesDelegateToApplicationAdapter(t *testing.T) {
	routes := &controlRoutesStub{}
	server := NewServer(&store.Store{})
	server.SetControlRoutes(routes)
	handler := adminTestHandler(server)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/control-commands", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/evidence-pullbacks", nil))

	if routes.commands != 1 || routes.evidence != 1 {
		t.Fatalf("commands=%d evidence=%d", routes.commands, routes.evidence)
	}
}

type controlRoutesStub struct{ commands, evidence int }

func (stub *controlRoutesStub) Commands(http.ResponseWriter, *http.Request) { stub.commands++ }
func (stub *controlRoutesStub) Evidence(http.ResponseWriter, *http.Request) { stub.evidence++ }
