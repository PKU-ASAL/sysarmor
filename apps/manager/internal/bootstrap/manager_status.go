package bootstrap

import statushttp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/adapters/inbound/http/status"

type ManagerStatus = statushttp.StorageStatus

func NewManagerStatusHTTP(status ManagerStatus) *statushttp.Handler {
	return statushttp.NewHandler(status)
}
