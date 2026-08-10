package enrollment

import (
	"context"
	"fmt"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type ListEnrollmentsQuery struct{ Status domainenrollment.Status }

type EnrollmentView struct {
	Enrollment      domainenrollment.Enrollment
	Unenrollment    domainenrollment.Unenrollment
	HasUnenrollment bool
}

type ListEnrollmentsResult struct{ Enrollments []EnrollmentView }

type QueryService struct{ uow ports.EnrollmentUnitOfWork }

func NewQueryService(uow ports.EnrollmentUnitOfWork) *QueryService { return &QueryService{uow: uow} }

func (service *QueryService) List(ctx context.Context, request managerapp.RequestContext, query ListEnrollmentsQuery) (ListEnrollmentsResult, error) {
	if err := request.Actor.Require(tenant.RoleViewer); err != nil {
		return ListEnrollmentsResult{}, err
	}
	var result ListEnrollmentsResult
	err := service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		enrollments, err := tx.Enrollments().List(txCtx, request.Actor.TenantID, query.Status)
		if err != nil {
			return fmt.Errorf("list enrollments: %w", err)
		}
		unenrollments, err := tx.Unenrollments().List(txCtx, request.Actor.TenantID)
		if err != nil {
			return fmt.Errorf("list unenrollments: %w", err)
		}
		result.Enrollments = projectEnrollments(enrollments, unenrollments)
		return nil
	})
	return result, err
}

func projectEnrollments(enrollments []domainenrollment.Enrollment, unenrollments []domainenrollment.Unenrollment) []EnrollmentView {
	byID := make(map[string]domainenrollment.Unenrollment, len(unenrollments))
	for _, value := range unenrollments {
		byID[value.Identity.EnrollmentID] = value
	}
	result := make([]EnrollmentView, 0, len(enrollments))
	for _, value := range enrollments {
		unenrollment, ok := byID[value.ID]
		result = append(result, EnrollmentView{Enrollment: value, Unenrollment: unenrollment, HasUnenrollment: ok})
	}
	return result
}
