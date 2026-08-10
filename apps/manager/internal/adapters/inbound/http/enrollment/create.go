package enrollment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

const defaultEnrollmentTTL = 24 * time.Hour

type createRequest struct {
	TenantID          string            `json:"tenant_id,omitempty"`
	AgentID           string            `json:"agent_id,omitempty"`
	HostID            string            `json:"host_id,omitempty"`
	GatewayAddress    string            `json:"gateway_addr"`
	GatewayServerName string            `json:"gateway_sni,omitempty"`
	Profile           string            `json:"profile,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	TTL               string            `json:"ttl,omitempty"`
}

type enrollmentDocument struct {
	EnrollmentID          string            `json:"enrollment_id"`
	TenantID              string            `json:"tenant_id"`
	AgentID               string            `json:"agent_id,omitempty"`
	HostID                string            `json:"host_id,omitempty"`
	TokenPreview          string            `json:"token_preview,omitempty"`
	BootstrapTokenPreview string            `json:"bootstrap_token_preview,omitempty"`
	GatewayAddress        string            `json:"gateway_addr"`
	GatewayServerName     string            `json:"gateway_sni,omitempty"`
	Profile               string            `json:"profile,omitempty"`
	Labels                map[string]string `json:"labels,omitempty"`
	Status                string            `json:"status"`
	CreatedAt             time.Time         `json:"created_at"`
	ExpiresAt             time.Time         `json:"expires_at"`
	CreatedBy             string            `json:"created_by,omitempty"`
}

func (handler *Handler) Enrollments(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		handler.listEnrollments(writer, request)
	case http.MethodPost:
		handler.createEnrollment(writer, request)
	default:
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
	}

}

func (handler *Handler) createEnrollment(writer http.ResponseWriter, request *http.Request) {
	requestContext, ok := handler.resolveRequest(writer, request)
	if !ok {
		return
	}
	command, err := decodeCreateCommand(request, requestContext)
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	result, err := handler.create.Execute(request.Context(), requestContext, command)
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"enrollment": mapEnrollment(result.Enrollment), "token": result.Token,
		"install_url": handler.enrollmentInstallURL(request, result.BootstrapTicket)})
}

type enrollmentViewDocument struct {
	enrollmentDocument
	UnenrollmentStatus string     `json:"unenrollment_status,omitempty"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	EndpointCompleted  *time.Time `json:"endpoint_completed_at,omitempty"`
}

func (handler *Handler) listEnrollments(writer http.ResponseWriter, request *http.Request) {
	requestContext, ok := handler.resolveRequest(writer, request)
	if !ok {
		return
	}
	result, err := handler.query.List(request.Context(), requestContext, enrollmentapp.ListEnrollmentsQuery{
		Status: domainenrollment.Status(strings.TrimSpace(request.URL.Query().Get("status"))),
	})
	if err != nil {
		writeCreateError(writer, err)
		return
	}
	values := make([]enrollmentViewDocument, 0, len(result.Enrollments))
	for _, value := range result.Enrollments {
		values = append(values, mapEnrollmentView(value))
	}
	writeJSON(writer, map[string]any{"enrollments": values})
}

func mapEnrollmentView(value enrollmentapp.EnrollmentView) enrollmentViewDocument {
	document := enrollmentViewDocument{enrollmentDocument: mapEnrollment(value.Enrollment)}
	if !value.HasUnenrollment {
		return document
	}
	document.UnenrollmentStatus = string(value.Unenrollment.Status)
	document.RevokedAt = timePointer(value.Unenrollment.RevokedAt)
	document.EndpointCompleted = timePointer(value.Unenrollment.CompletedAt)
	return document
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func (handler *Handler) resolveRequest(writer http.ResponseWriter, request *http.Request) (managerapp.RequestContext, bool) {
	if handler.resolve == nil {
		writeCreateError(writer, failure.New(failure.Unauthenticated, "unauthorized"))
		return managerapp.RequestContext{}, false
	}
	value, err := handler.resolve(request)
	if err != nil {
		writeCreateError(writer, err)
		return managerapp.RequestContext{}, false
	}
	return value, true
}

func decodeCreateCommand(request *http.Request, requestContext managerapp.RequestContext) (enrollmentapp.CreateEnrollmentCommand, error) {
	var input createRequest
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		return enrollmentapp.CreateEnrollmentCommand{}, failure.New(failure.InvalidArgument, fmt.Sprintf("decode enrollment: %v", err))
	}
	ttl := defaultEnrollmentTTL
	var err error
	if strings.TrimSpace(input.TTL) != "" {
		ttl, err = time.ParseDuration(input.TTL)
		if err != nil {
			return enrollmentapp.CreateEnrollmentCommand{}, failure.New(failure.InvalidArgument, fmt.Sprintf("ttl: %v", err))
		}
	}
	tenantID := strings.TrimSpace(input.TenantID)
	if tenantID == "" {
		tenantID = requestContext.Actor.TenantID.String()
	}
	return enrollmentapp.CreateEnrollmentCommand{TenantID: tenantID, AgentID: input.AgentID, HostID: input.HostID,
		GatewayAddress: input.GatewayAddress, GatewayServerName: input.GatewayServerName,
		Profile: input.Profile, Labels: input.Labels, TTL: ttl}, nil
}

func mapEnrollment(value domainenrollment.Enrollment) enrollmentDocument {
	return enrollmentDocument{EnrollmentID: value.ID, TenantID: value.TenantID.String(), AgentID: value.AgentID,
		HostID: value.HostID, TokenPreview: value.TokenPreview, BootstrapTokenPreview: value.BootstrapTokenPreview,
		GatewayAddress: value.GatewayAddress, GatewayServerName: value.GatewayServerName, Profile: value.Profile,
		Labels: value.Labels, Status: string(value.Status), CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt,
		CreatedBy: value.CreatedBy}
}

func (handler *Handler) enrollmentInstallURL(request *http.Request, ticket string) string {
	relative := (&url.URL{Path: "/api/v1/agent-install.sh", RawQuery: url.Values{"ticket": []string{ticket}}.Encode()}).String()
	if configured, err := url.Parse(strings.TrimSpace(handler.publicURL)); err == nil && configured.IsAbs() && configured.Host != "" {
		return strings.TrimRight(configured.String(), "/") + relative
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + relative
}

func writeCreateError(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch failure.KindOf(err) {
	case failure.InvalidArgument, failure.FailedPrecondition:
		status = http.StatusBadRequest
	case failure.Unauthenticated:
		status = http.StatusUnauthorized
	case failure.PermissionDenied:
		status = http.StatusForbidden
	case failure.NotFound:
		status = http.StatusNotFound
	case failure.Conflict:
		status = http.StatusConflict
	}
	http.Error(writer, err.Error(), status)
}
