package enrollment

import (
	"context"
	"fmt"
	"strings"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/tenant"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/ports"
)

type CreateEnrollmentCommand struct {
	TenantID          string
	AgentID           string
	HostID            string
	GatewayAddress    string
	GatewayServerName string
	Profile           string
	Labels            map[string]string
	TTL               time.Duration
}

type CreateEnrollmentResult struct {
	Enrollment      domainenrollment.Enrollment
	Token           string
	BootstrapTicket string
}

type CreateService struct {
	uow    ports.EnrollmentUnitOfWork
	tokens ports.EnrollmentTokenGenerator
	clock  ports.Clock
	ids    ports.IDGenerator
}

func NewCreateService(uow ports.EnrollmentUnitOfWork, tokens ports.EnrollmentTokenGenerator, clock ports.Clock, ids ports.IDGenerator) *CreateService {
	return &CreateService{uow: uow, tokens: tokens, clock: clock, ids: ids}
}

func (service *CreateService) Execute(ctx context.Context, request managerapp.RequestContext, command CreateEnrollmentCommand) (CreateEnrollmentResult, error) {
	tenantID, err := authorizeCreate(request, command)
	if err != nil {
		return CreateEnrollmentResult{}, err
	}
	if err := validateCreateCommand(command); err != nil {
		return CreateEnrollmentResult{}, err
	}
	token, bootstrap, err := service.newTokens()
	if err != nil {
		return CreateEnrollmentResult{}, err
	}
	now := service.clock.Now()
	value, err := domainenrollment.NewEnrollment(newEnrollmentValue(command, tenantID, request.Actor.Subject, service.ids.New(), token, bootstrap, now))
	if err != nil {
		return CreateEnrollmentResult{}, err
	}
	var pending CreateEnrollmentResult
	err = service.uow.Execute(ctx, func(txCtx context.Context, tx ports.EnrollmentTransaction) error {
		if err := tx.Enrollments().Put(txCtx, value); err != nil {
			return fmt.Errorf("put enrollment: %w", err)
		}
		pending = CreateEnrollmentResult{Enrollment: value, Token: token.Plaintext, BootstrapTicket: bootstrap.Plaintext}
		return nil
	})
	if err != nil {
		return CreateEnrollmentResult{}, err
	}
	return pending, nil
}

func authorizeCreate(request managerapp.RequestContext, command CreateEnrollmentCommand) (tenant.ID, error) {
	if err := request.Actor.Require(tenant.RoleOperator); err != nil {
		return "", err
	}
	tenantID, err := tenant.NewID(command.TenantID)
	if err != nil {
		return "", err
	}
	if tenantID != request.Actor.TenantID {
		return "", failure.New(failure.PermissionDenied, "enrollment tenant does not match actor tenant")
	}
	return tenantID, nil
}

func (service *CreateService) newTokens() (ports.EnrollmentToken, ports.EnrollmentToken, error) {
	if service == nil || service.uow == nil || service.tokens == nil || service.clock == nil || service.ids == nil {
		return ports.EnrollmentToken{}, ports.EnrollmentToken{}, failure.New(failure.Internal, "enrollment create service is incomplete")
	}
	first, err := service.tokens.New()
	if err != nil {
		return ports.EnrollmentToken{}, ports.EnrollmentToken{}, fmt.Errorf("generate enrollment token: %w", err)
	}
	second, err := service.tokens.New()
	return first, second, err
}

func validateCreateCommand(command CreateEnrollmentCommand) error {
	if err := domainenrollment.ValidateIdentity(command.TenantID, command.AgentID); err != nil {
		return err
	}
	if err := domainenrollment.ValidateGateway(command.GatewayAddress, command.GatewayServerName); err != nil {
		return err
	}
	if command.TTL <= 0 {
		return failure.New(failure.InvalidArgument, "ttl must be positive")
	}
	if profile := strings.TrimSpace(command.Profile); profile != "" && profile != "linux-systemd" && profile != "linux-container" {
		return failure.New(failure.InvalidArgument, "install profile is unsupported")
	}
	return nil
}

func newEnrollmentValue(command CreateEnrollmentCommand, tenantID tenant.ID, createdBy, id string, token, bootstrap ports.EnrollmentToken, now time.Time) domainenrollment.Enrollment {
	hostID := strings.TrimSpace(command.HostID)
	if hostID == "" {
		hostID = strings.TrimSpace(command.AgentID)
	}
	profile := strings.TrimSpace(command.Profile)
	if profile == "" {
		profile = "linux-systemd"
	}
	return domainenrollment.Enrollment{ID: id, TenantID: tenantID, AgentID: strings.TrimSpace(command.AgentID), HostID: hostID,
		TokenHash: token.Hash, TokenPreview: token.Preview, BootstrapTokenHash: bootstrap.Hash,
		BootstrapTokenPreview: bootstrap.Preview, GatewayAddress: strings.TrimSpace(command.GatewayAddress),
		GatewayServerName: strings.TrimSpace(command.GatewayServerName), Profile: profile, Labels: command.Labels,
		CreatedBy: strings.TrimSpace(createdBy), Status: domainenrollment.StatusActive, CreatedAt: now.UTC(), ExpiresAt: now.Add(command.TTL).UTC()}
}
