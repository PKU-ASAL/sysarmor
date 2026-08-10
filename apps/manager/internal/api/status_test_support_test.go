package managerapi

import (
	statushttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/status"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"
)

func setTestStatusRoutes(server *Server, memory *store.Store) {
	info := memory.Info()
	server.SetStatusRoutes(statushttp.NewHandler(statushttp.StorageStatus{Backend: info.Backend, Path: info.Path,
		StateVersion: info.StateVersion, MigrationVersion: info.MigrationVersion,
		PostgresSchemaVersion: info.PostgresSchema}))
}
