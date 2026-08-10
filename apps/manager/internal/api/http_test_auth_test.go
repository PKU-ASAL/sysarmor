package managerapi

import (
	"net/http"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/auth"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

type authenticatedTestServer struct {
	*Server
	principal managerauth.Principal
}

func newAdminTestServer(st *store.Store) *authenticatedTestServer {
	server := NewServer()
	setTestIdentityApplication(server, st)
	setTestTelemetryApplication(server, st)
	return &authenticatedTestServer{
		Server: server,
		principal: managerauth.Principal{
			Subject: "test-admin", TenantID: "default", Roles: []string{"admin"},
		},
	}
}

func adminTestHandler(server *Server) http.Handler {
	if _, unavailable := server.telemetryRoutes.(unavailableTelemetryRoutes); unavailable && server.searcher != nil {
		setTestTelemetryApplication(server, nil)
	}
	return (&authenticatedTestServer{
		Server: server,
		principal: managerauth.Principal{
			Subject: "test-admin", TenantID: "default", Roles: []string{"admin"},
		},
	}).Handler()
}

func (s *authenticatedTestServer) Handler() http.Handler {
	next := s.Server.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(managerauth.WithPrincipal(r.Context(), s.principal)))
	})
}

func withTestPrincipal(req *http.Request, subject, tenantID string, roles ...string) *http.Request {
	principal := managerauth.Principal{Subject: subject, TenantID: tenantID, Roles: roles}
	return req.WithContext(managerauth.WithPrincipal(req.Context(), principal))
}
