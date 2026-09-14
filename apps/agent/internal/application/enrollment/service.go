package enrollment

import (
	"context"
	"sync"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/application/lifecycle"
	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/ports"
)

type EnrollmentCommand struct {
	Context       lifecycle.RequestContext
	ManagerURL    string
	Token         string
	UploadHistory bool
}

type UnenrollmentCommand struct {
	Context lifecycle.RequestContext
}

type Controller interface {
	Enroll(context.Context, EnrollmentCommand) lifecycle.Result
	Unenroll(context.Context, UnenrollmentCommand) lifecycle.Result
}

type Service struct {
	lifecycleCtx context.Context
	store        ports.EnrollmentStore
	runtime      ports.EnrollmentRuntime
	mu           sync.Mutex
}

func NewService(lifecycleCtx context.Context, store ports.EnrollmentStore, runtime ports.EnrollmentRuntime) *Service {
	return &Service{lifecycleCtx: lifecycleCtx, store: store, runtime: runtime}
}

func (s *Service) result(request lifecycle.RequestContext, status lifecycle.Status, message string) lifecycle.Result {
	identity := s.runtime.Identity()
	return lifecycle.Result{
		RequestID: request.RequestID,
		TenantID:  identity.TenantID,
		AgentID:   identity.AgentID,
		Status:    status,
		Message:   message,
	}
}
