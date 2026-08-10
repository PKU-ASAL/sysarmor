package artifact

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	managerapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager"
	artifactapp "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/application/manager/artifact"
	domainartifact "github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/artifact"
	"github.com/sysarmor/sysarmor-next-project/apps/manager/internal/domain/failure"
)

func (handler *Handler) upload(writer http.ResponseWriter, request *http.Request, requestContext managerapp.RequestContext) {
	if err := request.ParseMultipartForm(64 << 20); err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, fmt.Sprintf("parse artifact upload: %v", err)))
		return
	}
	file, header, err := request.FormFile("file")
	if err != nil {
		writeFailure(writer, failure.New(failure.InvalidArgument, fmt.Sprintf("file is required: %v", err)))
		return
	}
	defer file.Close()
	command := artifactapp.UploadCommand{Name: strings.TrimSpace(request.FormValue("name")),
		Kind: strings.TrimSpace(request.FormValue("kind")), Version: strings.TrimSpace(request.FormValue("version")),
		OS: request.FormValue("os"), Arch: request.FormValue("arch"), Filename: header.Filename,
		Status: domainartifact.Status(strings.TrimSpace(request.FormValue("status"))), Content: file}
	if command.Name == "" || command.Kind == "" || command.Version == "" {
		writeFailure(writer, failure.New(failure.InvalidArgument, "name, kind, and version are required"))
		return
	}
	artifact, err := handler.options.Service.Upload(request.Context(), requestContext, command)
	if err != nil {
		writeFailure(writer, err)
		return
	}
	writeJSON(writer, map[string]any{"artifact": mapArtifact(artifact),
		"download_url": artifactDownloadURL(request, artifact.ID)})
}

func artifactDownloadURL(request *http.Request, artifactID string) string {
	return absoluteURL(request, "/api/v1/artifacts/"+url.PathEscape(artifactID)+"/download")
}

func absoluteURL(request *http.Request, requestPath string) string {
	if publicURL := strings.TrimSpace(os.Getenv("SYSARMOR_PUBLIC_URL")); publicURL != "" {
		if parsed, err := url.Parse(publicURL); err == nil && parsed.IsAbs() && parsed.Host != "" {
			return strings.TrimRight(publicURL, "/") + "/" + strings.TrimLeft(requestPath, "/")
		}
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, request.Host, requestPath)
}
