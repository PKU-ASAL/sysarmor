package managerapi

import (
	"net/http"

	managerauth "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/auth"
	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
)

func PolicyRequestContext(r *http.Request) (managerapp.RequestContext, error) {
	principal, ok := managerauth.PrincipalFromContext(r.Context())
	if !ok {
		return managerapp.RequestContext{}, failure.New(failure.Unauthenticated, "unauthorized")
	}
	tenantID, err := tenant.NewID(principal.TenantID)
	if err != nil {
		return managerapp.RequestContext{}, err
	}
	roles := make([]tenant.Role, 0, len(principal.Roles))
	for _, role := range principal.Roles {
		switch role {
		case "viewer":
			roles = append(roles, tenant.RoleViewer)
		case "operator":
			roles = append(roles, tenant.RoleOperator)
		case "admin":
			roles = append(roles, tenant.RoleAdmin)
		}
	}
	return managerapp.RequestContext{Actor: tenant.Actor{
		Subject: principal.Subject, TenantID: tenantID, Roles: tenant.NewRoleSet(roles...),
	}}, nil
}
