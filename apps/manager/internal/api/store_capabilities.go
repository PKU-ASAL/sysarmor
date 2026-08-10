package managerapi

import "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/store"

type ManagerStore interface {
	EnsureDefaultPolicy(string)
	EnsureDefaultPolicyWithError(string) error
}

var _ ManagerStore = (*store.Store)(nil)
