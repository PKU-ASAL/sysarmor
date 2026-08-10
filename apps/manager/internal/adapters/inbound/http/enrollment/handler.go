package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	enrollmentapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/enrollment"
	domainenrollment "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/enrollment"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

type IssueService interface {
	Execute(context.Context, enrollmentapp.IssueCertificateCommand) (enrollmentapp.IssueCertificateResult, error)
}

type CompletionService interface {
	Execute(context.Context, enrollmentapp.CompleteUnenrollmentCommand) (enrollmentapp.CompleteUnenrollmentResult, error)
}

type CreateService interface {
	Execute(context.Context, managerapp.RequestContext, enrollmentapp.CreateEnrollmentCommand) (enrollmentapp.CreateEnrollmentResult, error)
}

type QueryService interface {
	List(context.Context, managerapp.RequestContext, enrollmentapp.ListEnrollmentsQuery) (enrollmentapp.ListEnrollmentsResult, error)
}

type DeploymentQueryService interface {
	DeploymentOptions(context.Context, managerapp.RequestContext) (enrollmentapp.DeploymentOptionsResult, error)
}

type BootstrapService interface {
	Redeem(context.Context, enrollmentapp.RedeemBootstrapCommand) (enrollmentapp.RedeemBootstrapResult, error)
}

type ArtifactService interface {
	Authorize(context.Context, enrollmentapp.AuthorizeArtifactCommand) (enrollmentapp.AuthorizeArtifactResult, error)
}

type InstallScriptRenderer interface {
	Render(*http.Request, domainenrollment.Enrollment, string) (string, error)
}

type RequestContextResolver func(*http.Request) (managerapp.RequestContext, error)

type Handler struct {
	create                  CreateService
	query                   QueryService
	deployment              DeploymentQueryService
	bootstrap               BootstrapService
	artifact                ArtifactService
	install                 InstallScriptRenderer
	issue                   IssueService
	completion              CompletionService
	resolve                 RequestContextResolver
	publicURL               string
	artifactDir             string
	deployGatewayAddress    string
	deployGatewayServerName string
	packageDownloadBaseURL  string
}

type Options struct {
	Create                  CreateService
	Query                   QueryService
	DeploymentQuery         DeploymentQueryService
	Bootstrap               BootstrapService
	Artifact                ArtifactService
	InstallScript           InstallScriptRenderer
	Issue                   IssueService
	Completion              CompletionService
	Resolve                 RequestContextResolver
	PublicURL               string
	ArtifactDir             string
	DeployGatewayAddress    string
	DeployGatewayServerName string
	PackageDownloadBaseURL  string
}

func NewHandler(options Options) *Handler {
	return &Handler{create: options.Create, query: options.Query, deployment: options.DeploymentQuery, bootstrap: options.Bootstrap,
		artifact: options.Artifact, install: options.InstallScript, issue: options.Issue,
		completion: options.Completion, resolve: options.Resolve, publicURL: options.PublicURL,
		artifactDir: options.ArtifactDir, deployGatewayAddress: options.DeployGatewayAddress,
		deployGatewayServerName: options.DeployGatewayServerName, packageDownloadBaseURL: options.PackageDownloadBaseURL}
}

type certificateRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

func (handler *Handler) Certificate(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input certificateRequest
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		http.Error(writer, fmt.Sprintf("decode certificate request: %v", err), http.StatusBadRequest)
		return
	}
	result, err := handler.issue.Execute(request.Context(), enrollmentapp.IssueCertificateCommand{
		TokenHash: hashToken(input.Token), CSR: []byte(input.CSR),
	})
	if err != nil {
		writeIssueError(writer, err)
		return
	}
	writeCertificate(writer, result)
}

func writeCertificate(writer http.ResponseWriter, result enrollmentapp.IssueCertificateResult) {
	value, certificate := result.Enrollment, result.Enrollment.Issuance.Certificate
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"schema_version": "sysarmor.enrollment/v2", "tenant_id": value.TenantID.String(),
		"agent_id": value.AgentID, "enrollment_id": value.ID, "gateway_address": value.GatewayAddress,
		"gateway_server_name": value.GatewayServerName, "certificate_pem": certificate.CertificatePEM,
		"ca_pem": value.Issuance.CAPEM, "serial_number": certificate.SerialNumber, "not_after": certificate.NotAfter,
	})
}

func writeIssueError(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch failure.KindOf(err) {
	case failure.InvalidArgument:
		status = http.StatusBadRequest
	case failure.NotFound:
		status = http.StatusNotFound
	case failure.Conflict:
		status = http.StatusConflict
	case failure.FailedPrecondition:
		status = http.StatusGone
	}
	http.Error(writer, err.Error(), status)
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}
