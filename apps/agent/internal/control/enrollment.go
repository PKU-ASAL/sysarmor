package control

import (
	"context"
	"sync"
	"time"

	"github.com/sysarmor/sysarmor-next-project/apps/agent/internal/localstore"
)

type EnrollmentCommand struct {
	Context       RequestContext
	ManagerURL    string
	Token         string
	UploadHistory bool
}

type UnenrollmentCommand struct {
	Context RequestContext
}

type EnrollmentController interface {
	Enroll(context.Context, EnrollmentCommand) Result
	Unenroll(context.Context, UnenrollmentCommand) Result
}

type EnrollmentIdentity struct {
	TenantID string
	AgentID  string
}

type EnrollmentPreparation struct {
	Enrollment localstore.Enrollment
	Handle     any
}

type EnrollmentStore interface {
	Enrollment(context.Context) (localstore.Enrollment, error)
	Stats(context.Context) (localstore.Stats, error)
	SetEnrolling(context.Context, localstore.Enrollment) error
	BeginUnenrollment(context.Context) (localstore.Enrollment, error)
	PrepareUnenrollment(context.Context, string, string) (localstore.Enrollment, error)
	UnenrollmentCompletion(context.Context) (localstore.UnenrollmentCompletion, bool, error)
	RecordUnenrollmentError(context.Context, string) error
	ConfirmEnrollmentRevocation(context.Context, string, time.Time) error
	CompleteUnenrollment(context.Context, string) error
}

type EnrollmentRuntime interface {
	EnrollmentIdentity() EnrollmentIdentity
	PrepareEnrollment(context.Context, string, string) (EnrollmentPreparation, error)
	RollbackEnrollment(EnrollmentPreparation, error) error
	FinalizeEnrollment(EnrollmentPreparation)
	StopEnrollmentNetwork()
	ReconcileEnrollment(localstore.Enrollment) error
	WithPolicyAuthority(func() error) error
	RevokeEnrollment(context.Context, localstore.Enrollment, string) (string, time.Time, error)
	RestoreStandalonePolicy(context.Context, func(context.Context) error) error
	RemoveEnrollmentCredentials(localstore.Enrollment) error
	ReportUnenrollmentCompletion(context.Context) (bool, error)
}

type EnrollmentCoordinator struct {
	lifecycleCtx context.Context
	store        EnrollmentStore
	runtime      EnrollmentRuntime
	mu           sync.Mutex
}

func NewEnrollmentCoordinator(lifecycleCtx context.Context, store EnrollmentStore, runtime EnrollmentRuntime) *EnrollmentCoordinator {
	return &EnrollmentCoordinator{lifecycleCtx: lifecycleCtx, store: store, runtime: runtime}
}

func (c *EnrollmentCoordinator) result(request RequestContext, status, message string) Result {
	identity := c.runtime.EnrollmentIdentity()
	return Result{
		RequestID: request.RequestID,
		TenantID:  identity.TenantID,
		AgentID:   identity.AgentID,
		Status:    status,
		Message:   message,
	}
}
